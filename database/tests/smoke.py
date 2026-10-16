"""Integration smoke test for the graph layer.

Needs a FalkorDB reachable at FALKORDB_HOST:FALKORDB_PORT (default 127.0.0.1:6379). It uses throwaway graph names, so it
never touches the real 'blastradius' graphs. Run:  python database/tests/smoke.py
"""
import os

os.environ.setdefault("FALKORDB_GRAPH", "blastradius_ci")
os.environ.setdefault("FALKORDB_ACCOUNTS_GRAPH", "blastradius_ci_accounts")

from blastradius_db import accounts, db, seed  # noqa: E402  (env must be set before the import)

# The graph contract the backend relies on: bounded-depth routes Internet -> crown jewel through exploitable hosts.
ATTACK_PATHS = """
MATCH p = (:Internet)-[:CAN_REACH*1..6]->(d:DataStore {crown: true})
WHERE all(n IN nodes(p) WHERE n:Internet OR n:DataStore OR size(n.xf) > 0)
RETURN [n IN nodes(p) | n.id]
"""


def main() -> None:
    assert db.GRAPH_NAME.endswith("ci"), "refusing to run against a non-CI graph"
    seed.load()
    assert seed.is_seeded(), "seed.load() should leave a seeded graph"
    assert db.run("MATCH (f:Finding) RETURN count(f)")[0][0] == 9, "9 findings expected"
    assert db.run("MATCH (n) WHERE n:Internet OR n:Host OR n:DataStore RETURN count(n)")[0][0] == 11, "11 nodes expected"

    paths = [r[0] for r in db.run(ATTACK_PATHS)]
    assert len(paths) == 4, f"4 attack paths expected, got {len(paths)}"
    # CVSS-10 / CVSS-9.8 decoys must not be on any path; the choke point must be on 3 of 4
    assert not any("legacy-ftp" in p or "batch-legacy" in p for p in paths)
    assert sum("api-gateway" in p for p in paths) == 3

    acct = accounts.upsert_account("ci-user", "pro", "ci@example.com", None)
    assert acct["plan"] == "pro" and accounts.get_account("ci-user")["plan"] == "pro"
    assert accounts.get_account("nobody")["plan"] == "free"
    print("database smoke test: OK")


if __name__ == "__main__":
    try:
        main()
    finally:  # always remove the throwaway graphs
        for g in (db.GRAPH_NAME, db.ACCOUNTS_GRAPH):
            try:
                db._get_client().select_graph(g).delete()
            except Exception:
                pass
