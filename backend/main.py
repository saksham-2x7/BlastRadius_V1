"""BlastRadius engine API. Run: uvicorn main:app --port 8000"""
import config  # noqa: F401  (loads backend/.env; must stay the first import)
import contextlib
import os
import secrets
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import ValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

import anyio
import engine
import enrich
import ingest
import threat_tools
from blastradius_db import accounts, db
from mcp_server import mcp


PRODUCTION = os.getenv("APP_ENV") == "production"
if PRODUCTION and not os.getenv("ENGINE_API_KEY"):
    # Fail closed: a production engine without a key would be an open API on the public internet.
    raise RuntimeError("ENGINE_API_KEY must be set when APP_ENV=production")


def require_key(request: Request, x_engine_key: str | None = Header(default=None)) -> None:
    """If ENGINE_API_KEY is set, every request must carry it (only the Next.js server knows it)."""
    if request.url.path == "/healthz":  # liveness probe for the platform: no data, no key
        return
    expected = os.getenv("ENGINE_API_KEY")
    if expected and not secrets.compare_digest(x_engine_key or "", expected):
        raise HTTPException(status_code=401, detail="Invalid or missing engine key")


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI):
    async with mcp.session_manager.run():  # the mounted MCP app needs its session manager running
        yield


app = FastAPI(
    title="BlastRadius engine",
    version="0.5.0",
    dependencies=[Depends(require_key)],
    lifespan=lifespan,
    # Interactive docs and the OpenAPI schema are not behind the key, so don't publish them in production.
    docs_url=None if PRODUCTION else "/docs",
    redoc_url=None if PRODUCTION else "/redoc",
    openapi_url=None if PRODUCTION else "/openapi.json",
)


class McpKeyGate:
    """Pure-ASGI gate: the mounted /mcp app is outside FastAPI's dependencies, so enforce ENGINE_API_KEY here."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        expected = os.getenv("ENGINE_API_KEY")
        if scope["type"] == "http" and scope["path"].startswith("/mcp") and expected:
            given = dict(scope["headers"]).get(b"x-engine-key", b"").decode()
            if not secrets.compare_digest(given, expected):
                body = b'{"detail":"Invalid or missing engine key"}'
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
                await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)


class WorkspaceMiddleware:
    """Selects the FalkorDB graph for this request from the X-Workspace header (set only by the Next.js server, which
    sends the signed-in user's id). No header, or no imported graph yet: the shared sample."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        token = None
        if scope["type"] == "http":
            raw = dict(scope["headers"]).get(b"x-workspace", b"").decode()
            if raw and 0 < len(raw) <= 128 and all(c.isalnum() or c in "_.@-" for c in raw):
                graph = db.workspace_graph(raw)
                if scope["path"] == "/api/import" or await anyio.to_thread.run_sync(db.graph_exists, graph):
                    token = db.use_graph(graph)
        try:
            await self.app(scope, receive, send)
        finally:
            if token is not None:
                db.reset_graph(token)


app.add_middleware(McpKeyGate)
app.add_middleware(WorkspaceMiddleware)
def _cors_origins() -> list[str]:
    """Exact origins allowed to call this API from a browser. Production fails closed: no CORS_ORIGINS means none allowed."""
    raw = os.getenv("CORS_ORIGINS")
    if raw is None:
        return [] if PRODUCTION else ["http://localhost:3000"]
    origins = [o.strip().rstrip("/") for o in raw.split(",") if o.strip()]
    if "*" in origins:
        raise RuntimeError("CORS_ORIGINS must list exact origins, never '*'")
    if PRODUCTION and any(not o.startswith("https://") for o in origins):
        raise RuntimeError("In production every CORS origin must be https://")
    return origins


# The browser never talks to this API directly (the Next.js server calls it with the engine key), so CORS is defence in
# depth: only the deployed web app's origin is allowed, no cookies/credentials, and only the methods and headers we use.
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Engine-Key"],
    max_age=600,
)

ID_PATTERN = r"^[A-Za-z0-9_.@-]+$"


class FixRequest(BaseModel):
    finding_id: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_-]+$")


class AccountUpdate(BaseModel):
    user_id: str = Field(min_length=1, max_length=128, pattern=ID_PATTERN)
    plan: Literal["free", "pro"]
    email: str | None = Field(default=None, max_length=254)
    customer_id: str | None = Field(default=None, max_length=128, pattern=ID_PATTERN)


@app.exception_handler(db.EngineUnavailable)
async def _unavailable(_, exc: db.EngineUnavailable) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"error": "engine_unavailable", "message": str(exc), "host": db.HOST, "port": db.PORT},
    )


@app.exception_handler(db.EngineQueryError)
async def _query_error(_, exc: db.EngineQueryError) -> JSONResponse:
    return JSONResponse(status_code=500, content={"error": "query_failed", "message": str(exc)})


@app.exception_handler(engine.FixError)
async def _fix_error(_, exc: engine.FixError) -> JSONResponse:
    return JSONResponse(status_code=exc.status, content={"error": "fix_rejected", "message": exc.message})


@app.get("/healthz", include_in_schema=False)
def healthz() -> dict:
    """Cheap liveness check (does not touch FalkorDB). Use /api/health (needs the key) for a deep check."""
    return {"status": "ok"}


@app.get("/api/health")
def health() -> dict:
    db.run("RETURN 1")  # raises EngineUnavailable (503) if FalkorDB is down
    return {"status": "ok", "falkordb": f"{db.HOST}:{db.PORT}", "graph": db.GRAPH_NAME}


@app.post("/api/import")
def import_inventory(spec: ingest.ImportSpec) -> dict:
    """Load the caller's own inventory as a private workspace graph, enrich it with live KEV/EPSS, and return the scan."""
    if db.current_graph() == db.SAMPLE_GRAPH:
        raise HTTPException(status_code=400, detail="A workspace id is required to import.")
    with engine._lock:
        counts = ingest.build(spec)
    live = enrich.enrich_current_graph()
    return {"imported": counts, "live_feeds": live, "scan": engine.scan()}


@app.get("/api/scan")
def get_scan() -> dict:
    engine.expire_if_idle()  # a solved demo graph snaps back to the sample after a quiet spell (also seeds the graph)
    enrich.maybe_refresh_async()  # live KEV/EPSS, refreshed in the background (never blocks a scan)
    return engine.scan()


@app.post("/api/fix/auto")
def fix_auto(req: FixRequest) -> dict:
    return engine.apply_fix(req.finding_id, "auto")


@app.post("/api/fix/auto-all")
def fix_auto_all() -> dict:
    """Bulk auto-fix. The web server only forwards this for Pro accounts."""
    return engine.apply_all_auto()


@app.post("/api/fix/approve")
def fix_approve(req: FixRequest) -> dict:
    return engine.apply_fix(req.finding_id, "approved")


@app.post("/api/reset")
def reset() -> dict:
    return engine.reset()


@app.get("/api/tools")
def list_tools() -> list[dict[str, Any]]:
    """Tool catalogue (name, description, JSON schemas): what an LLM provider needs to declare its tools."""
    return [
        {"name": n, "description": d.description, "input_schema": d.input_model.model_json_schema(),
         "output_schema": d.output_model.model_json_schema(), "read_only": d.read_only}
        for n, d in threat_tools.TOOLS.items()
    ]


@app.post("/api/tools/{name}")
def call_tool(name: str, args: dict[str, Any] | None = None) -> Any:
    """Run one tool with Pydantic-validated arguments (same functions the MCP server exposes)."""
    tool = threat_tools.TOOLS.get(name)
    if tool is None:
        raise HTTPException(status_code=404, detail=f"Unknown tool '{name}'")
    try:
        parsed = tool.input_model.model_validate(args or {})
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors(include_url=False, include_context=False, include_input=False))
    try:
        return tool.call(parsed).model_dump()
    except threat_tools.ToolNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/api/account/{user_id}")
def get_account(user_id: str) -> dict:
    if not (0 < len(user_id) <= 128) or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.@-" for c in user_id):
        raise HTTPException(status_code=422, detail="Invalid user id")
    return accounts.get_account(user_id)


@app.get("/api/account-by-customer/{customer_id}")
def account_by_customer(customer_id: str) -> dict:
    return {"user_id": accounts.find_by_customer(customer_id)}


@app.post("/api/account")
def set_account(req: AccountUpdate) -> dict:
    return accounts.upsert_account(req.user_id, req.plan, req.email, req.customer_id)


# MCP over streamable HTTP, alongside the REST API: http://127.0.0.1:8000/mcp/
app.mount("/mcp", mcp.streamable_http_app())
