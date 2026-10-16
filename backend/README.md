# backend

FastAPI engine + MCP server. Deployed on **Railway** as a Docker image (build context = repo root).

## Run
```bash
cd backend
python3.12 -m venv .venv && .venv/bin/pip install -r requirements.txt   # also installs ../database as an editable package
cp ../keys/backend.env.example .env                                     # or run ../keys/setup.sh
.venv/bin/uvicorn main:app --port 8000
```
Needs a FalkorDB (see `../database`). Config: `config.py` loads `backend/.env`; real environment variables win.

## Files
```
main.py          FastAPI app: routes, key check, fail-closed CORS, /healthz, mounts MCP at /mcp/
engine.py        scan, ranking, autonomy tiers, apply_fix / apply_all_auto
threat_tools.py  the 3 read-only tools as typed Pydantic models (get_attack_paths, get_vulnerability_context, simulate_fix)
mcp_server.py    MCP server (stdio: `python mcp_server.py`; HTTP: mounted at /mcp/)
config.py        loads backend/.env (must be imported first)
Dockerfile, Dockerfile.dockerignore, railway.json
```

## API (all need `X-Engine-Key` except `/healthz`)
`GET /api/scan` · `POST /api/fix/auto|approve|auto-all` · `POST /api/reset` · `GET /api/tools` · `POST /api/tools/{name}` · `GET|POST /api/account` · `GET /api/health` (deep check) · MCP at `/mcp/`.

## Production behaviour (`APP_ENV=production`, set in the Dockerfile)
Refuses to start without `ENGINE_API_KEY`; hides `/docs`; CORS allows only the exact `https://` origins in `CORS_ORIGINS` (none if unset); the MCP host check needs `MCP_ALLOWED_HOSTS`.

## Docker
```bash
docker build -f backend/Dockerfile -t blastradius-backend .    # run from the REPO ROOT
```
Railway: Root Directory empty, config file path `backend/railway.json` (redeploys only when `backend/` or `database/` change).
