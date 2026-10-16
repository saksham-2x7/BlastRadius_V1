# BlastRadius

**See the attack paths. Fix what actually matters.**

**Live demo: [blastradius-ashy.vercel.app](https://blastradius-ashy.vercel.app)**

BlastRadius maps infrastructure as a graph in FalkorDB, finds every real route from the internet to your crown jewels, ranks findings by the attack paths they sit on (not CVSS), and fixes the few that cut them: automatically when low-risk, with human approval when not. An AI advisor reads the graph through MCP tools.


## Graph Hacks (WeMakeDevs x FalkorDB) · Track 1: Agents That Act on Connected Data

**The agent:** the BlastRadius advisor triages security findings and *acts*. It finds where one fix cuts the most routes to a crown jewel, simulates the fix, applies it if the graph says it is low-risk, escalates everything else to a human, and remembers what it did. Every step is a visible MCP tool call.

| Track 1 focus | How BlastRadius does it |
|---|---|
| Multi-hop reasoning | Bounded variable-length Cypher: `(:Internet)-[:CAN_REACH*1..6]->(:DataStore {crown:true})` through still-exploitable hosts |
| Graph algorithms as agent tools | `get_choke_points` = FalkorDB `algo.betweenness` + `algo.pageRank`; `explain_attack_path` = FalkorDB `algo.SPpaths` |
| Tool selection through MCP | A real MCP server (`backend/mcp_server.py`) and client (`frontend/lib/advisor/mcp.ts`); Gemini or Claude pick the tools |
| Actions based on what the graph shows | `apply_safe_fix` patches only findings whose **graph-computed tier** is `auto` (leaf host, one path). Choke points and crown-jewel neighbours are refused and handed to a human. The model cannot override the tier |
| Explainable results | Each answer cites the exact routes, path counts before/after (`simulate_fix`), and the tier reason. When the agent cites a route, the dashboard **draws it on the graph** (blue edges, ringed hosts) |
| Real public data | CISA KEV and FIRST EPSS are fetched live (`backend/enrich.py`, cached 24h, background refresh, snapshot fallback). The data notice in every answer says which one is in use |
| Acts in the real workflow | `draft_fix_ticket` writes a ready-to-file GitHub or Jira ticket from graph evidence (paths, KEV, EPSS, simulated impact, rollback). `file_github_issue` files it as a real GitHub issue when the deployment opts in (`GITHUB_TOKEN`, `GITHUB_REPO`), capped at 5/hour, only when the user asks |
| Your own data | "Use your own data" in the dashboard imports an inventory (hosts, data stores, reachability, findings, optional Trivy JSON) into a **private FalkorDB graph per user** (`ws_<hash>`). Every query and agent tool then runs on it unchanged; the shared sample is untouched. `POST /api/import`, validated and size-capped (`backend/ingest.py`) |
| Memory (bonus) | Per tenant: every decision, including refusals, is stored as `(:Agent)-[:DID]->(:AgentAction)-[:IN]->(:Workspace)` and recalled with `recall_agent_memory`, scoped to the workspace it was taken in. It survives chats and "restore demo" |

### Graph data model
```
(:Internet)-[:CAN_REACH]->(:Host)-[:CAN_REACH]->(:DataStore {crown})
(:Host)-[:HAS_FINDING]->(:Finding {cve, cvss, epss, kev, exploitable, patched})
(:Fix {mode, ts, rollback})-[:FIXES]->(:Finding)
(:Agent {name})-[:DID]->(:AgentAction {tool, finding_id, host, decision, rationale, paths_before, paths_after})   -- accounts graph
(:User {id, plan})                                                                                           -- accounts graph
-- one graph per workspace: the shared sample, or ws_<hash(user id)> for imported inventories (same schema)
```

### The Cypher and algorithms the product depends on
```cypher
// attack paths (backend/engine.py)
MATCH p = (:Internet)-[:CAN_REACH*1..6]->(d:DataStore {crown: true})
WHERE all(n IN nodes(p) WHERE n:Internet OR n:DataStore OR size(n.xf) > 0)
RETURN [n IN nodes(p) | n.id]

// what-if: same query with a finding treated as patched (backend/threat_tools.py, SIM_PATHS)
// choke points: FalkorDB betweenness centrality
CALL algo.betweenness({nodeLabels: ['Internet','Host','DataStore'], relationshipTypes: ['CAN_REACH']}) YIELD node, score
// shortest routes to the crown jewel
MATCH (s:Internet), (t:DataStore {crown: true})
CALL algo.SPpaths({sourceNode: s, targetNode: t, relationshipTypes: ['CAN_REACH'], pathCount: $n}) YIELD path
```

### What was built during the event vs. before
Honest timeline: the first version of the engine (FalkorDB sample graph, attack-path query, three read-only MCP tools, advisor wiring) was committed on Oct 13-14, before the event started. Built during the event (Oct 15-18): the agent's *action* tool with the graph-decided safety tier, FalkorDB algorithm tools (betweenness, shortest paths), persistent graph memory, the idle auto-restore of the shared demo graph, the full UI/landing/dashboard redesign, and the fixes listed in the git history.

### Run it
See "Run locally" below. Data: synthetic topology with real CVE ids; KEV and EPSS are live public feeds; CVSS is a snapshot. Tests (66): backend 33 (`cd backend && pip install -r requirements.txt pytest && pytest`) and frontend 33 (`cd frontend && npm test`). Backend unit tests cover the safety tiers, import validation and edge de-duplication, and the live-feed client with the network mocked; integration tests (run in CI against a real FalkorDB service) cover the agent's tools and refusals, the pitch story (4 paths to 0), per-user graphs and per-tenant memory. Frontend tests cover the engine client and its error mapping, signed checkout tokens, subscription handling and the advisor providers. Demo script: [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md). Blog post: [docs/BLOG.md](docs/BLOG.md). Demo video: add the link here before submitting.

## The four parts (work on one without touching the others)

| Folder | What it is | Stack | Deploys to | Own docs |
|---|---|---|---|---|
| [`frontend/`](frontend) | Web app: landing, Google sign-in, dashboard, billing, advisor UI | Next.js 16, React 19, Tailwind | **Vercel** (Root Directory = `frontend`) | [frontend/README](frontend/README.md) |
| [`backend/`](backend) | API + MCP server: scan, fixes, tiers, tools | FastAPI, MCP | **Railway** (Docker) | [backend/README](backend/README.md) |
| [`database/`](database) | Graph layer: FalkorDB connection, schema/seed, account store | Python package + FalkorDB | **Railway** (`falkordb` image) | [database/README](database/README.md) |
| [`keys/`](keys) | Every environment variable: templates, who needs what, setup/check scripts | shell | n/a (real values live in Vercel/Railway, never in git) | [keys/README](keys/README.md) |

```
 browser ──▶ frontend (Vercel) ──HTTP /api/* + MCP, X-Engine-Key──▶ backend (Railway) ──blastradius_db──▶ FalkorDB (Railway, private)
                 │  Google sign-in, Gemini/Claude advisor                                                       
                 └──── keys/ documents every secret and where it is set
```

### Boundaries (what makes the parts independent)
- **frontend ↔ backend:** only HTTP (`/api/*`) and MCP (`/mcp/`), authenticated by the `X-Engine-Key` header. The frontend never imports backend code.
- **backend ↔ database:** only the `blastradius_db` Python package (`database/`). The database package never imports the backend.
- **secrets:** only in environment variables. Templates are in `keys/`; real values never enter git (`keys/check.sh` verifies this).
- **CI:** `.github/workflows/` runs `frontend`, `backend` and `database` checks **only when that folder changes**.

## Run locally
```bash
keys/setup.sh                       # creates frontend/.env.local and backend/.env, generates matching secrets
# fill GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GEMINI_API_KEY in frontend/.env.local, then:
keys/check.sh                       # confirms keys are set, match, and nothing secret is tracked

docker compose -f database/docker-compose.yml up -d                       # 1) FalkorDB on :6379
cd backend && python3.12 -m venv .venv && .venv/bin/pip install -r requirements.txt \
  && .venv/bin/uvicorn main:app --port 8000                               # 2) API + MCP on :8000
cd frontend && npm install && npm run dev                                  # 3) web app on :3000
```

## Deploy (one-time platform settings)
- **Vercel:** Project → Settings → General → **Root Directory = `frontend`**. Env vars: see `keys/frontend.env.example`.
- **Railway, backend service:** Settings → Source → **clear the Root Directory** (repo root) and set the **config file path** to `backend/railway.json`. Env vars: `keys/backend.env.example`.
- **Railway, database service:** Docker image `falkordb/falkordb:latest`, a volume at `/var/lib/falkordb/data`, no public domain. Env vars: `keys/database.env.example`.

## AI disclosure
Built with AI coding assistants (Claude Code). All code was reviewed by the team.

## License
MIT. See [LICENSE](LICENSE).
