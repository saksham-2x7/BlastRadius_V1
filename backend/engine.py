"""Graph logic: attack paths, ranking, autonomy tiers, fixes. All decisions come from graph data."""
import os
import threading
import time
import uuid
from typing import Any

import enrich
from blastradius_db import seed
from blastradius_db import db
from blastradius_db.db import run

_lock = threading.Lock()  # serializes fixes so two clicks can't race each other
enrich.GRAPH_LOCK = _lock
_seeded = False

# The demo graph is shared by every visitor. Once someone applies fixes and then goes quiet, snap it back
# to the sample so the next visitor starts from the full set of attack paths. 0 disables the auto-restore.
# The "last change" time is read from the graph itself (every applied fix is stored with a timestamp), so it
# survives backend restarts and redeploys.
DEMO_RESET_MINUTES = float(os.getenv("DEMO_RESET_MINUTES", "10"))
_last_scan = 0.0  # unix time of the latest scan request: someone browsing the demo keeps it from snapping back under them

# Always bound depth (*1..6): unbounded variable-length paths can explode and hit the DB timeout.
ATTACK_PATHS = """
MATCH p = (:Internet)-[:CAN_REACH*1..6]->(d:DataStore {crown: true})
WHERE all(n IN nodes(p) WHERE n:Internet OR n:DataStore OR size(n.xf) > 0)
RETURN [n IN nodes(p) | n.id] AS path
"""


class FixError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _load_sample() -> None:
    """Reload the sample graph, then re-apply the live KEV/EPSS values if a feed refresh already succeeded."""
    seed.load()
    enrich.apply_cached()


def _is_sample() -> bool:
    return db.current_graph() == db.SAMPLE_GRAPH


def ensure_seeded() -> None:
    global _seeded
    if not _is_sample():  # an imported workspace is never auto-seeded
        return
    if _seeded:
        return
    with _lock:
        if not _seeded:
            if not seed.is_seeded():
                _load_sample()
            _seeded = True


def reset() -> dict[str, Any]:
    global _seeded
    if not _is_sample():
        raise FixError(409, "Restore only applies to the shared sample. Switch back to the sample data first.")
    with _lock:
        _load_sample()
        _seeded = True
    return scan()


def _last_fix_ms() -> int | None:
    rows = run("MATCH (x:Fix) RETURN max(x.ts)")
    return int(rows[0][0]) if rows and rows[0][0] is not None else None


def _idle_for_too_long() -> bool:
    last = _last_fix_ms()
    if last is None:
        return False
    last = max(last, int(_last_scan * 1000))  # a fix or a recent scan both count as activity
    return time.time() * 1000 - last >= DEMO_RESET_MINUTES * 60_000


def expire_if_idle() -> bool:
    """Restore the sample graph if fixes were applied and nobody has changed anything for DEMO_RESET_MINUTES."""
    global _seeded, _last_scan
    if DEMO_RESET_MINUTES <= 0 or not _is_sample():
        return False
    ensure_seeded()
    if _idle_for_too_long():
        with _lock:
            if _idle_for_too_long():  # someone was active while we waited for the lock
                _load_sample()
                _seeded = True
                _last_scan = time.time()
                return True
    _last_scan = time.time()  # this request itself is activity
    return False


def scan() -> dict[str, Any]:
    ensure_seeded()
    paths: list[list[str]] = [r[0] for r in run(ATTACK_PATHS)]
    node_rows = run("MATCH (n) WHERE n:Internet OR n:Host OR n:DataStore RETURN labels(n)[0], n.id, n.crown, n.software, n.role")
    edge_rows = run("MATCH (a)-[:CAN_REACH]->(b) RETURN a.id, b.id")
    finding_rows = run(
        """MATCH (h:Host)-[:HAS_FINDING]->(f:Finding)
           RETURN f.id, f.cve, f.cvss, f.epss, f.kev, f.exploitable, f.patched, h.id, f.product, f.summary"""
    )
    crown_neighbours = {r[0] for r in run("MATCH (h:Host)-[:CAN_REACH]->(:DataStore {crown: true}) RETURN h.id")}
    history_rows = run(
        """MATCH (x:Fix)-[:FIXES]->(f:Finding)<-[:HAS_FINDING]-(h:Host)
           RETURN x.id, f.id, f.cve, h.id, x.mode, x.ts, x.rollback ORDER BY x.ts DESC"""
    )

    # How many attack paths run through each host.
    load: dict[str, int] = {}
    for p in paths:
        for host in p:
            load[host] = load.get(host, 0) + 1
    internal = {h: c for h, c in load.items() if h not in ("internet",) and not _is_datastore(h, node_rows)}
    max_load = max(internal.values(), default=0)
    chokes = {h for h, c in internal.items() if c == max_load and max_load > 1}

    findings: list[dict[str, Any]] = []
    for fid, cve, cvss, epss, kev, exploitable, patched, host, product, summary in finding_rows:
        on_paths = load.get(host, 0) if (exploitable and not patched) else 0
        tier, reason = _tier(
            exploitable=bool(exploitable), patched=bool(patched), on_paths=on_paths,
            total=len(paths), host=host, chokes=chokes, crown_neighbours=crown_neighbours,
        )
        findings.append({
            "id": fid, "cve": cve, "host": host, "cvss": cvss, "epss": epss, "kev": bool(kev),
            "exploitable": bool(exploitable), "patched": bool(patched),
            "paths": on_paths, "tier": tier, "reason": reason, "product": product, "summary": summary,
        })
    findings.sort(key=lambda f: (-f["paths"], -f["cvss"]))

    hot: set[tuple[str, str]] = {(p[i], p[i + 1]) for p in paths for i in range(len(p) - 1)}
    kind_of = {"Internet": "internet", "Host": "host", "DataStore": "datastore"}
    kev_hosts = {f["host"] for f in findings if f["kev"] and not f["patched"]}
    nodes: list[dict[str, Any]] = [
        {"id": nid, "kind": kind_of[label], "crown": bool(crown), "choke": nid in chokes, "paths": load.get(nid, 0),
         "kev": nid in kev_hosts, "software": software, "role": role}
        for label, nid, crown, software, role in node_rows
    ]
    edges: list[dict[str, Any]] = [
        {"source": a, "target": b, "type": "CAN_REACH", "hot": (a, b) in hot} for a, b in edge_rows
    ]
    for f in findings:  # vulnerability nodes hang off their host
        nodes.append({
            "id": f["id"], "kind": "vulnerability", "host": f["host"], "cve": f["cve"], "cvss": f["cvss"],
            "exploitable": f["exploitable"], "patched": f["patched"], "paths": f["paths"], "crown": False, "choke": False,
            "kev": f["kev"], "epss": f["epss"],
        })
        edges.append({"source": f["host"], "target": f["id"], "type": "HAS_FINDING", "hot": False})

    summary = {
        "paths": len(paths),
        "exploitable": sum(1 for f in findings if f["exploitable"] and not f["patched"]),
        "auto": sum(1 for f in findings if f["tier"] == "auto"),
        "approval": sum(1 for f in findings if f["tier"] == "approval"),
        "monitor": sum(1 for f in findings if f["tier"] == "monitor"),
        "patched": sum(1 for f in findings if f["patched"]),
    }
    history = [
        {"id": r[0], "finding_id": r[1], "cve": r[2], "host": r[3], "mode": r[4], "ts": r[5], "rollback": r[6]}
        for r in history_rows
    ]
    summary["kev"] = sum(1 for f in findings if f["kev"] and not f["patched"])
    return {"summary": summary, "paths": paths, "nodes": nodes, "edges": edges, "findings": findings,
            "history": history, "data_notice": enrich.notice(),
            "workspace": "sample" if _is_sample() else "own"}


def _is_datastore(node_id: str, node_rows: list[list[Any]]) -> bool:
    return any(row[1] == node_id and row[0] == "DataStore" for row in node_rows)


def _tier(*, exploitable: bool, patched: bool, on_paths: int, total: int, host: str,
          chokes: set[str], crown_neighbours: set[str]) -> tuple[str, str]:
    """Deterministic autonomy tier from graph facts only (never a model's opinion)."""
    if patched:
        return "patched", "Fix applied"
    if on_paths == 0:
        return "monitor", ("Not reachable on any path to a crown jewel" if exploitable
                           else "Low exploit likelihood (EPSS < 0.1, not in KEV)")
    if host in chokes:
        return "approval", f"Choke point: sits on {on_paths} of {total} paths"
    if host in crown_neighbours:
        return "approval", "Directly adjacent to a crown jewel"
    if on_paths > 1:
        return "approval", f"Sits on {on_paths} paths: wide blast radius"
    return "auto", "Leaf host on a single path: reversible patch"


def apply_all_auto(max_fixes: int = 50) -> dict[str, Any]:
    """Apply every auto-tier fix, re-evaluating tiers after each one (a fix can change the others' tiers)."""
    paths_before = scan()["summary"]["paths"]
    applied: list[str] = []
    for _ in range(max_fixes):
        nxt = next((f for f in scan()["findings"] if f["tier"] == "auto"), None)
        if nxt is None:
            break
        try:
            apply_fix(nxt["id"], "auto")
            applied.append(nxt["id"])
        except FixError as exc:
            if exc.status != 409:  # 409 = a concurrent request got there first; re-scan and continue
                raise
    final = scan()
    return {"applied": applied, "paths_before": paths_before, "paths_after": final["summary"]["paths"], "scan": final}


def apply_fix(finding_id: str, mode: str) -> dict[str, Any]:
    """mode 'auto' only for auto-tier findings; mode 'approved' only for approval-tier ones (the human click)."""
    with _lock:
        before = scan()
        target = next((f for f in before["findings"] if f["id"] == finding_id), None)
        if target is None:
            raise FixError(404, f"Unknown finding {finding_id}")
        if target["patched"]:
            raise FixError(409, f"{finding_id} is already patched")
        if mode == "auto" and target["tier"] != "auto":
            raise FixError(409, f"{finding_id} is tier '{target['tier']}': it cannot be auto-applied")
        if mode == "approved" and target["tier"] != "approval":
            raise FixError(409, f"{finding_id} is tier '{target['tier']}': nothing to approve")

        rollback = (f"Revert {target['cve']} on {target['host']}: restore previous package version / config snapshot")
        run(
            """MATCH (f:Finding {id: $fid}) SET f.patched = true
               CREATE (:Fix {id: $xid, mode: $mode, ts: $ts, rollback: $rollback})-[:FIXES]->(f)""",
            {"fid": finding_id, "xid": f"FIX-{uuid.uuid4().hex[:6]}", "mode": mode,
             "ts": int(time.time() * 1000), "rollback": rollback},
        )
        seed.recompute_exploitable_hosts()
        after = scan()
    return {
        "fixed": finding_id, "mode": mode,
        "paths_before": before["summary"]["paths"], "paths_after": after["summary"]["paths"],
        "scan": after,
    }
