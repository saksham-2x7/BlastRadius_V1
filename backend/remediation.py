"""A real fix output: a runnable Ansible remediation playbook with a rollback path, using fixed versions looked up live from OSV.

BlastRadius never touches your servers. It decides which fixes matter and hands you a reviewed-by-a-human artifact:
run it with `--check --diff` first. Fixed versions come from OSV (https://osv.dev), free and keyless, cached for a day.
"""
import json
import re
import time
import urllib.error
import urllib.request
from typing import Any

OSV_URL = "https://api.osv.dev/v1/vulns/"
TTL_SECONDS = 24 * 3600
_cache: dict[str, tuple[float, list[dict[str, str]]]] = {}
OS_ECOSYSTEMS = ("Debian", "Ubuntu", "Alpine", "Red Hat", "Rocky", "AlmaLinux", "SUSE", "openSUSE")  # real OS package managers only


def _osv(vuln_id: str) -> dict[str, Any] | None:
    try:
        req = urllib.request.Request(OSV_URL + vuln_id, headers={"User-Agent": "blastradius-demo/1.0"})
        with urllib.request.urlopen(req, timeout=8) as r:  # noqa: S310 (fixed https host)
            return json.loads(r.read())
    except Exception:  # 404, network, JSON: no fixed version known
        return None


def fixed_versions(cve: str) -> list[dict[str, str]]:
    """[{ecosystem, package, fixed, source}] from OSV: the CVE record first, then its aliases (GHSA ids carry package ranges)."""
    hit = _cache.get(cve)
    if hit and time.time() - hit[0] < TTL_SECONDS:
        return hit[1]
    queue, seen, out = [cve], set(), []
    while queue and len(seen) < 4:
        vid = queue.pop(0)
        if vid in seen:
            continue
        seen.add(vid)
        rec = _osv(vid)
        if not rec:
            continue
        queue += [a for a in rec.get("aliases", []) if a not in seen][:3]
        for aff in rec.get("affected", []):
            pkg = aff.get("package") or {}
            eco, name = str(pkg.get("ecosystem", "")), pkg.get("name")
            if not (eco and name):
                continue
            for rng in aff.get("ranges", []):
                if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                    continue
                for ev in rng.get("events", []):
                    if ev.get("fixed"):
                        out.append({"ecosystem": eco.split(":")[0], "package": str(name), "fixed": str(ev["fixed"]), "source": vid})
    uniq: list[dict[str, str]] = []
    for o in out:
        if not any((u["package"], u["fixed"]) == (o["package"], o["fixed"]) for u in uniq):
            uniq.append(o)
    _cache[cve] = (time.time(), uniq[:8])
    return _cache[cve][1]


def _vkey(version: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", version)[:6])


def best_fix(cands: list[dict[str, str]], product: str | None) -> dict[str, str] | None:
    """Pick the package that matches the finding's product (else any), then the HIGHEST fixed version: OSV lists one fixed
    version per release branch (for example 2.3.2, 2.12.4 and 2.17.1), and the newest is the safe upgrade for every branch."""
    if not cands:
        return None
    p = (product or "").lower()
    named = [c for c in cands if p and ((n := c["package"].lower().rsplit(":", 1)[-1]) in p or p in n)]
    pool = named or cands
    top = max(pool, key=lambda c: _vkey(c["fixed"]))
    others = sorted({c["fixed"] for c in pool if c["package"] == top["package"] and c["fixed"] != top["fixed"]}, key=_vkey)
    return {**top, "also_fixed_in": ", ".join(others)}


def _q(s: str) -> str:
    return json.dumps(s)  # a JSON string is a valid double-quoted YAML scalar


def build_playbook(fixes: list[dict[str, Any]]) -> str:
    """fixes: [{finding_id, cve, host, product, mode, fix: {ecosystem, package, fixed, source} | None}] -> Ansible YAML text."""
    lines = [
        "# BlastRadius remediation playbook, generated from the attack-path graph.",
        "# Review it, then run:  ansible-playbook remediation.yml --check --diff   (dry run first)",
        "#                       ansible-playbook remediation.yml                  (apply)",
        "#                       ansible-playbook remediation.yml -e rollback=true (undo; set previous_versions below)",
        "# Fixed versions are looked up live from OSV (https://osv.dev). Verify them against your vendor advisory.",
        "---",
    ]
    by_host: dict[str, list[dict[str, Any]]] = {}
    for f in fixes:
        by_host.setdefault(f["host"], []).append(f)
    if not by_host:
        lines += ["- name: Nothing to remediate", "  hosts: localhost", "  gather_facts: false", "  tasks: []"]
        return "\n".join(lines) + "\n"
    for host, items in by_host.items():
        lines += [f"- name: {_q('Remediate ' + host)}", f"  hosts: {_q(host)}", "  become: true", "  gather_facts: false",
                  "  vars:", "    app_dir: /srv/app", "    previous_versions: {}  # e.g. { \"log4j-core\": \"2.14.1\" }", "  tasks:"]
        for f in items:
            fx, cve = f.get("fix"), f["cve"]
            title = f"{cve} on {host}" + (f" ({f['product']})" if f.get("product") else "")
            note = f"# {f['finding_id']}: {'applied automatically' if f.get('mode') == 'auto' else 'approved by a human' if f.get('mode') == 'approved' else 'proposed'}"
            lines.append(f"    {note}")
            if fx and fx.get("also_fixed_in"):
                lines.append(f"    # OSV also lists fixed releases {fx['also_fixed_in']} for older branches; the newest is used here")
            if not fx:
                lines += [f"    - name: {_q(title + ': no machine-readable fix found')}",
                          f"      ansible.builtin.debug: {{ msg: {_q('No fixed version found in OSV. Read https://nvd.nist.gov/vuln/detail/' + cve + ' and patch manually.')} }}",
                          f"      tags: [{cve}]"]
                continue
            eco, pkg, ver = fx["ecosystem"], fx["package"], fx["fixed"]
            short = pkg.rsplit(":", 1)[-1]
            when_fix, when_back = "when: not (rollback | default(false) | bool)", "when: rollback | default(false) | bool"
            if eco == "npm":
                fix_t = ("ansible.builtin.command", f"{{ chdir: \"{{{{ app_dir }}}}\", cmd: {_q(f'npm install --save {pkg}@{ver}')} }}")
                back_t = ("ansible.builtin.command", f"{{ chdir: \"{{{{ app_dir }}}}\", cmd: \"npm install --save {pkg}@{{{{ previous_versions['{pkg}'] }}}}\" }}")
            elif eco == "PyPI":
                fix_t = ("ansible.builtin.command", f"{{ cmd: {_q(f'python3 -m pip install {pkg}>={ver}')} }}")
                back_t = ("ansible.builtin.command", f"{{ cmd: \"python3 -m pip install {pkg}=={{{{ previous_versions['{pkg}'] }}}}\" }}")
            elif eco.split(" ")[0] in OS_ECOSYSTEMS or eco in OS_ECOSYSTEMS:
                fix_t = ("ansible.builtin.package", f"{{ name: {_q(short)}, state: latest }}")
                back_t = ("ansible.builtin.package", f"{{ name: \"{short}={{{{ previous_versions['{short}'] }}}}\", state: present }}")
            else:
                msg = f"Upgrade {pkg} to >= {ver} ({eco}) in your build file, then rebuild and redeploy."
                fix_t = ("ansible.builtin.debug", f"{{ msg: {_q(msg)} }}")
                back_t = None
            lines += [f"    - name: {_q(title + ': upgrade to >= ' + ver)}", f"      {fix_t[0]}: {fix_t[1]}", f"      {when_fix}",
                      f"      tags: [{cve}, fix]  # source: OSV {fx['source']}"]
            if back_t:
                lines += [f"    - name: {_q(title + ': roll back')}", f"      {back_t[0]}: {back_t[1]}", f"      {when_back}", f"      tags: [{cve}, rollback]"]
    return "\n".join(lines) + "\n"
