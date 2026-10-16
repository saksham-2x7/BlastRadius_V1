# database

The graph layer: how BlastRadius talks to **FalkorDB**. A small installable Python package (`blastradius_db`) that the backend imports. It reads only `FALKORDB_*` environment variables and imports nothing from the backend.

## Run FalkorDB locally
```bash
docker compose -f database/docker-compose.yml up -d     # FalkorDB :6379, browser UI http://localhost:3001
python database/tests/smoke.py                          # integration test (throwaway graphs, needs `pip install ./database`)
```

## Package
```
blastradius_db/db.py        connection (host/port/password/TLS), run(query, params, graph), 503-style errors
blastradius_db/seed.py      sample workspace: schema + data (real CVE ids, illustrative CVSS/KEV/EPSS, synthetic topology)
blastradius_db/accounts.py  user plans: (:User {id, plan, customer_id}) in a SEPARATE graph so "reset" never wipes subscriptions
tests/smoke.py              seeds a CI graph and asserts the contract below
```

## Graph model
```
(:Internet)-[:CAN_REACH]->(:Host)-[:CAN_REACH]->(:DataStore {crown})
(:Host)-[:HAS_FINDING]->(:Finding {cve, cvss, epss, kev, exploitable, patched, product, summary})
(:Host {xf: [ids of unpatched exploitable findings]})      -- derived from findings, recomputed after every fix
(:Fix {id, mode, ts, rollback})-[:FIXES]->(:Finding)
```
Core query (bounded depth, always `*1..6`):
```cypher
MATCH p = (:Internet)-[:CAN_REACH*1..6]->(d:DataStore {crown: true})
WHERE all(n IN nodes(p) WHERE n:Internet OR n:DataStore OR size(n.xf) > 0)
RETURN [n IN nodes(p) | n.id]
```

## Production (Railway, service `falkordb`)
Docker image `falkordb/falkordb:latest`, volume at `/var/lib/falkordb/data`, **no public domain**. Variables in `../keys/database.env.example`. FalkorDB algorithm names on this image: `algo.labelPropagation`, `algo.maxFlow`, `algo.pageRank`, `algo.betweenness`, `algo.WCC`, `algo.BFS`, `algo.SPpaths`, `algo.SSpaths`, `algo.MSF`.
