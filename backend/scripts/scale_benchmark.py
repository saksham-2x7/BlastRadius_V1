"""Scale benchmark: how the engine and the agent's graph tools behave as the network grows.

Builds a layered synthetic network (internet-facing tier -> middle tiers -> crown-jewel databases) of N hosts, every host with
one exploitable finding, then times the real code paths. Run against a throwaway FalkorDB:
    FALKORDB_PORT=6391 LIVE_FEEDS=0 python scripts/scale_benchmark.py 50 200 500 1000
"""
import os
import random
import statistics
import sys
import time

os.environ.setdefault("LIVE_FEEDS", "0")
os.environ.setdefault("FALKORDB_GRAPH", "scale_bench")
os.environ.setdefault("FALKORDB_ACCOUNTS_GRAPH", "scale_bench_acc")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import engine  # noqa: E402
import ingest  # noqa: E402
import threat_tools as t  # noqa: E402
from blastradius_db import db  # noqa: E402

TIERS, FANOUT = int(os.getenv("TIERS", "5")), int(os.getenv("FANOUT", "2"))
CVES = ["CVE-2021-44228", "CVE-2021-41773", "CVE-2014-0160", "CVE-2021-23017", "CVE-2022-24999", "CVE-2014-6271"]


def spec(n: int) -> ingest.ImportSpec:
    rnd = random.Random(7)
    per = max(2, n // TIERS)
    tiers = [[f"h{ti}-{i}" for i in range(per)] for ti in range(TIERS)]
    edges = [(a, b) for ti in range(TIERS - 1) for a in tiers[ti] for b in rnd.sample(tiers[ti + 1], min(FANOUT, per))]
    stores = [{"id": f"db{i}", "crown": True} for i in range(3)]
    edges += [(a, s["id"]) for a in tiers[-1] for s in rnd.sample(stores, 1)]
    hosts = [{"id": h, "exposed": ti == 0} for ti, tier in enumerate(tiers) for h in tier]
    findings = [{"host": h["id"], "cve": rnd.choice(CVES), "cvss": 9.0} for h in hosts]
    return ingest.ImportSpec.model_validate({"hosts": hosts, "datastores": stores, "edges": [list(e) for e in edges], "findings": findings})


def timed(fn, repeat=3):
    runs = []
    for _ in range(repeat):
        t0 = time.perf_counter()
        out = fn()
        runs.append((time.perf_counter() - t0) * 1000)
    return statistics.median(runs), out


def main(sizes: list[int]) -> None:
    print("| hosts | edges | attack paths | build | scan | choke points | route | blast zone | apply fix |")
    print("|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for n in sizes:
        token = db.use_graph(f"ws_scale_{n}")
        try:
            s = spec(n)
            t0 = time.perf_counter()
            ingest.build(s)
            build = (time.perf_counter() - t0) * 1000
            scan_ms, scan = timed(engine.scan)
            choke_ms, _ = timed(lambda: t.get_choke_points(5))
            route_ms, _ = timed(lambda: t.explain_attack_path(3))
            zone_ms, _ = timed(lambda: t.get_blast_zone(s.hosts[0].id))
            fix_ms, _ = timed(lambda: t.apply_safe_fix(scan["findings"][0]["id"], "benchmark"), repeat=1)
            print(f"| {len(s.hosts)} | {len(s.edges)} | {scan['summary']['paths']} | {build:.0f} ms | {scan_ms:.0f} ms | {choke_ms:.0f} ms | "
                  f"{route_ms:.0f} ms | {zone_ms:.0f} ms | {fix_ms:.0f} ms |", flush=True)
        finally:
            db.delete_graph()
            db.reset_graph(token)


if __name__ == "__main__":
    main([int(x) for x in sys.argv[1:]] or [50, 200, 500])
