"""Live public threat feeds: CISA KEV (known exploited) and FIRST EPSS (exploit probability).

CVSS stays an embedded snapshot (NVD needs an API key). If a feed cannot be reached, the sample keeps its snapshot values
and the data notice says so: the demo never breaks because a government site is slow.
"""
import json
import os
import threading
import time
import urllib.parse
import urllib.request
from typing import Any

from blastradius_db import seed
from blastradius_db.db import run

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
ENABLED = os.getenv("LIVE_FEEDS", "1") != "0"
TTL_SECONDS = float(os.getenv("FEED_TTL_HOURS", "24")) * 3600

_cache: dict[str, Any] | None = None  # {"kev": set[str], "epss": {cve: float}, "at": unix seconds}
_running = False
_failed_at = 0.0
_guard = threading.Lock()
GRAPH_LOCK = threading.Lock()  # engine.py replaces this with its own lock so feed writes never race a fix


def _get(url: str, timeout: float = 12.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "blastradius-demo/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (fixed https URLs above)
        return r.read()


def fetch(cves: list[str]) -> dict[str, Any] | None:
    """Download KEV + EPSS for these CVE ids. Returns None if anything fails."""
    try:
        kev = {v["cveID"] for v in json.loads(_get(KEV_URL, 20))["vulnerabilities"]}
        epss: dict[str, float] = {}
        for i in range(0, len(cves), 50):
            q = urllib.parse.urlencode({"cve": ",".join(cves[i:i + 50])}, safe=",")
            for d in json.loads(_get(f"{EPSS_URL}?{q}"))["data"]:
                epss[d["cve"]] = float(d["epss"])
        return {"kev": kev, "epss": epss, "at": time.time()}
    except Exception:  # network, JSON or schema problem: fall back to the snapshot
        return None


def enrich_current_graph() -> bool:
    """Fetch live KEV/EPSS for the CVEs in the CURRENT graph (an imported workspace) and apply them. False if unreachable."""
    global _cache
    if not ENABLED:
        return False
    try:
        cves = [r[0] for r in run("MATCH (f:Finding) RETURN DISTINCT f.cve")]
        if not cves:
            return False
        have = _cache["epss"] if _cache else {}
        kev = _cache["kev"] if _cache else {v["cveID"] for v in json.loads(_get(KEV_URL, 20))["vulnerabilities"]}
        epss = dict(have)
        missing = [c for c in cves if c not in have]
        for i in range(0, len(missing), 50):
            q = urllib.parse.urlencode({"cve": ",".join(missing[i:i + 50])}, safe=",")
            for d in json.loads(_get(f"{EPSS_URL}?{q}"))["data"]:
                epss[d["cve"]] = float(d["epss"])
        _cache = {"kev": kev, "epss": epss, "at": time.time()}
        apply_cached()
        return True
    except Exception:
        return False


def apply_cached() -> None:
    """Write the cached live values onto the Finding nodes and recompute which hosts are still exploitable."""
    if not _cache:
        return
    rows = [r[0] for r in run("MATCH (f:Finding) RETURN DISTINCT f.cve")]
    for cve in rows:
        epss = _cache["epss"].get(cve)
        kev = cve in _cache["kev"]
        if epss is None:
            run("MATCH (f:Finding {cve: $c}) SET f.kev = $k, f.exploitable = ($k OR f.epss >= 0.1)", {"c": cve, "k": kev})
        else:
            run("MATCH (f:Finding {cve: $c}) SET f.kev = $k, f.epss = $e, f.exploitable = ($k OR $e >= 0.1)",
                {"c": cve, "k": kev, "e": epss})
    seed.recompute_exploitable_hosts()


def _refresh() -> None:
    global _cache, _running, _failed_at
    try:
        cves = [r[0] for r in run("MATCH (f:Finding) RETURN DISTINCT f.cve")]
        if not cves:  # graph not seeded yet: nothing to enrich, try again on the next scan
            return
        data = fetch(cves)
        if data:
            _cache = data
            with GRAPH_LOCK:
                apply_cached()
        else:
            _failed_at = time.time()
    finally:
        _running = False


def maybe_refresh_async() -> None:
    """Kick off a background refresh if the cache is stale. Never blocks a request."""
    global _running
    if not ENABLED:
        return
    now = time.time()
    if _cache and now - _cache["at"] < TTL_SECONDS:
        return
    if _failed_at and now - _failed_at < 600:  # back off 10 minutes after a failure
        return
    with _guard:
        if _running:
            return
        _running = True
    threading.Thread(target=_refresh, daemon=True, name="feed-refresh").start()


def notice() -> str:
    if _cache:
        when = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(_cache["at"]))
        return (f"CVE ids are real. CISA KEV and FIRST EPSS are live public feeds (fetched {when}). "
                "CVSS values are a snapshot. The infrastructure topology is synthetic.")
    return seed.DATA_NOTICE
