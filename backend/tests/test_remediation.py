"""Fixed-version lookup (OSV mocked) and Ansible playbook generation. Pure functions, no database needed."""
import pytest

import remediation

yaml = pytest.importorskip("yaml")

GHSA = {"id": "GHSA-jfh8", "aliases": ["CVE-2021-44228"], "affected": [{
    "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0-beta9"}, {"fixed": "2.15.0"}]}]}]}
CVE = {"id": "CVE-2021-44228", "aliases": ["GHSA-jfh8"], "affected": [{"ranges": [{"type": "GIT", "events": [{"fixed": "abc123"}]}]}]}


@pytest.fixture(autouse=True)
def osv(monkeypatch):
    remediation._cache.clear()
    monkeypatch.setattr(remediation, "_osv", lambda vid: {"CVE-2021-44228": CVE, "GHSA-jfh8": GHSA}.get(vid))


def test_fixed_version_is_found_through_the_alias():
    got = remediation.fixed_versions("CVE-2021-44228")
    assert got == [{"ecosystem": "Maven", "package": "org.apache.logging.log4j:log4j-core", "fixed": "2.15.0", "source": "GHSA-jfh8"}]


def test_unknown_cve_gives_no_candidates_and_never_raises():
    assert remediation.fixed_versions("CVE-2099-0001") == []


def test_best_fix_prefers_the_matching_product_and_the_newest_fixed_release():
    cands = [{"package": "a:other", "fixed": "9.9", "ecosystem": "Maven", "source": "x"},
             {"package": "org.apache.logging.log4j:log4j-core", "fixed": "2.3.2", "ecosystem": "Maven", "source": "x"},
             {"package": "org.apache.logging.log4j:log4j-core", "fixed": "2.17.1", "ecosystem": "Maven", "source": "x"},
             {"package": "org.apache.logging.log4j:log4j-core", "fixed": "2.12.4", "ecosystem": "Maven", "source": "x"}]
    best = remediation.best_fix(cands, "log4j-core")
    assert best["fixed"] == "2.17.1" and best["also_fixed_in"] == "2.3.2, 2.12.4"
    assert remediation.best_fix([], "x") is None


def fix(eco, pkg, ver, mode="approved"):
    return {"finding_id": "F1", "cve": "CVE-2021-0001", "host": "api-gateway", "product": pkg, "mode": mode,
            "fix": {"ecosystem": eco, "package": pkg, "fixed": ver, "source": "OSV-1"}}


@pytest.mark.parametrize("eco,pkg", [("npm", "qs"), ("PyPI", "requests"), ("Debian", "openssl"), ("Maven", "org.x:y"), ("Go", "golang.org/x/net"), ("Bitnami", "nginx")])
def test_playbook_is_valid_yaml_for_every_ecosystem(eco, pkg):
    doc = yaml.safe_load(remediation.build_playbook([fix(eco, pkg, "1.2.3")]))
    play = doc[0]
    assert play["hosts"] == "api-gateway" and play["tasks"][0]["tags"][0] == "CVE-2021-0001"
    assert any("fix" in t.get("tags", []) for t in play["tasks"])


def test_os_and_npm_fixes_have_a_rollback_and_manual_ones_do_not():
    npm = yaml.safe_load(remediation.build_playbook([fix("npm", "qs", "6.9.7")]))[0]["tasks"]
    assert [t["tags"][-1] for t in npm] == ["fix", "rollback"]
    maven = yaml.safe_load(remediation.build_playbook([fix("Maven", "org.x:y", "2.17.1")]))[0]["tasks"]
    assert [t["tags"][-1] for t in maven] == ["fix"]


def test_missing_fix_is_reported_not_invented_and_empty_playbook_is_valid():
    row = fix("npm", "qs", "1")
    row["fix"] = None
    task = yaml.safe_load(remediation.build_playbook([row]))[0]["tasks"][0]
    assert "no machine-readable fix" in task["name"] and "nvd.nist.gov" in task["ansible.builtin.debug"]["msg"]
    assert yaml.safe_load(remediation.build_playbook([]))[0]["tasks"] == []
