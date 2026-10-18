"""Live public threat feeds: CISA KEV (known exploited) and FIRST EPSS (exploit probability).

CVSS stays an embedded snapshot (NVD needs an API key). If a feed cannot be reached, the sample keeps its snapshot values
and the data notice says so: the demo never breaks because a government site is slow.
"""
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from blastradius_db import db, seed
from blastradius_db.db import run

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_MAX = int(os.getenv("NVD_MAX_PER_REFRESH", "20"))  # NVD allows 5 requests / 30 s without an API key
ENABLED = os.getenv("LIVE_FEEDS", "1") != "0"
TTL_SECONDS = float(os.getenv("FEED_TTL_HOURS", "24")) * 3600

_cache: dict[str, Any] | None = None  # {"kev": set[str], "epss": {cve: float}, "at": unix seconds}
_running = False
_failed_at = 0.0
_guard = threading.Lock()
GRAPH_LOCK = threading.Lock()  # engine.py replaces this with its own lock so feed writes never race a fix


_nvd: dict[str, float] = {}  # cve -> CVSS base score fetched from NVD
_nvd_running = False


def _get(url: str, timeout: float = 12.0, headers: dict[str, str] | None = None) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "blastradius-demo/1.0", **(headers or {})})
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
        start_nvd_async(cves)
        return True
    except Exception:
        return False


def _nvd_score(cve: str) -> float | None:
    """CVSS base score for one CVE from the NVD API (v3.1, then v3.0, v4.0, v2), or None if NVD has no score."""
    key = os.getenv("NVD_API_KEY")
    data = json.loads(_get(f"{NVD_URL}?{urllib.parse.urlencode({'cveId': cve})}", 12, {"apiKey": key} if key else None))
    metrics = data["vulnerabilities"][0]["cve"]["metrics"]
    for name in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        if metrics.get(name):
            return float(metrics[name][0]["cvssData"]["baseScore"])
    return None


def _nvd_fill(cves: list[str], graph: str) -> None:
    """Background: fetch CVSS from NVD for CVEs not seen yet, politely (rate limit), and write it onto the findings."""
    global _nvd_running
    token = db.use_graph(graph)
    try:
        delay = 0.7 if os.getenv("NVD_API_KEY") else 6.5
        for cve in [c for c in cves if c not in _nvd][:NVD_MAX]:
            try:
                score = _nvd_score(cve)
            except urllib.error.HTTPError as exc:
                if exc.code in (403, 429, 503):  # rate limited or down: stop, try again on a later refresh
                    break
                continue
            except Exception:
                continue
            if score is not None:
                _nvd[cve] = score
                with GRAPH_LOCK:
                    run("MATCH (f:Finding {cve: $c}) SET f.cvss = $s", {"c": cve, "s": score})
            time.sleep(delay)
    finally:
        db.reset_graph(token)
        _nvd_running = False


def start_nvd_async(cves: list[str]) -> None:
    """Start the NVD CVSS refresh for the CURRENT graph in the background, if enabled and there is something new to fetch."""
    global _nvd_running
    if not ENABLED or os.getenv("NVD_LIVE", "1") == "0" or not [c for c in cves if c not in _nvd]:
        return
    with _guard:
        if _nvd_running:
            return
        _nvd_running = True
    threading.Thread(target=_nvd_fill, args=(cves, db.current_graph()), daemon=True, name="nvd-refresh").start()


def apply_cached() -> None:
    """Write the cached live values onto the Finding nodes and recompute which hosts are still exploitable."""
    if not _cache:
        return
    rows = [r[0] for r in run("MATCH (f:Finding) RETURN DISTINCT f.cve")]
    for cve in rows:
        epss = _cache["epss"].get(cve)
        kev = cve in _cache["kev"]
        if cve in _nvd:
            run("MATCH (f:Finding {cve: $c}) SET f.cvss = $s", {"c": cve, "s": _nvd[cve]})
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
            start_nvd_async(cves)
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
        cvss = "NVD CVSS scores are live where fetched" if _nvd else "CVSS values are a snapshot"
        return (f"CVE ids are real. CISA KEV and FIRST EPSS are live public feeds (fetched {when}); {cvss}. "
                "The infrastructure topology is synthetic.")
    return seed.DATA_NOTICE
