"""FalkorDB connection. Plain TCP, so it works the same against Docker, a self-hosted server or FalkorDB Cloud."""
import contextvars
import hashlib
import os
import threading
from typing import Any

from falkordb import FalkorDB
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import ResponseError
from redis.exceptions import TimeoutError as RedisTimeoutError

# Configuration comes from environment variables only (FALKORDB_*). The service that imports this package decides where
# they come from (backend/.env locally, platform variables in production), so this package never reads files itself.
HOST = os.getenv("FALKORDB_HOST", "127.0.0.1")
PORT = int(os.getenv("FALKORDB_PORT", "6379"))
USERNAME = os.getenv("FALKORDB_USERNAME") or None
PASSWORD = os.getenv("FALKORDB_PASSWORD") or None
USE_TLS = os.getenv("FALKORDB_SSL", "").lower() in ("1", "true", "yes")  # for managed services that require TLS
GRAPH_NAME = os.getenv("FALKORDB_GRAPH", "blastradius")
# User accounts / subscriptions live in their own graph so "reset sample data" can never wipe them.
ACCOUNTS_GRAPH = os.getenv("FALKORDB_ACCOUNTS_GRAPH", "blastradius_accounts")
SAMPLE_GRAPH = GRAPH_NAME

# One FalkorDB graph per workspace: the shared sample, or a user's own imported inventory (graph "ws_<hash of user id>").
# The active graph is a context variable, set per request by the API middleware, so engine code just calls run().
_current: contextvars.ContextVar[str | None] = contextvars.ContextVar("graph", default=None)


def current_graph() -> str:
    return _current.get() or GRAPH_NAME


def workspace_graph(user_id: str) -> str:
    return "ws_" + hashlib.sha1(user_id.encode()).hexdigest()[:20]


def use_graph(name: str) -> contextvars.Token:
    return _current.set(name)


def reset_graph(token: contextvars.Token) -> None:
    _current.reset(token)


def graph_exists(name: str) -> bool:
    try:
        return name in _get_client().list_graphs()
    except (RedisConnectionError, RedisTimeoutError, OSError):
        return False


class EngineUnavailable(Exception):
    """FalkorDB cannot be reached (mapped to HTTP 503)."""


class EngineQueryError(Exception):
    """FalkorDB reachable, but the query failed or timed out (mapped to HTTP 500)."""


_client: FalkorDB | None = None
_lock = threading.Lock()


def _get_client() -> FalkorDB:
    global _client
    with _lock:
        if _client is None:
            _client = FalkorDB(
                host=HOST,
                port=PORT,
                username=USERNAME,
                password=PASSWORD,
                ssl=USE_TLS,
                socket_connect_timeout=2,
                socket_timeout=10,
            )
        return _client


def _reset_client() -> None:
    global _client
    with _lock:
        _client = None


def run(query: str, params: dict[str, Any] | None = None, graph: str | None = None) -> list[list[Any]]:
    """Run one Cypher query and return its rows. Raises EngineUnavailable / EngineQueryError."""
    try:
        return _get_client().select_graph(graph or current_graph()).query(query, params or {}).result_set
    except (RedisConnectionError, RedisTimeoutError, ConnectionRefusedError, OSError) as exc:
        _reset_client()
        raise EngineUnavailable(f"Cannot reach FalkorDB at {HOST}:{PORT} ({type(exc).__name__}).") from exc
    except ResponseError as exc:
        raise EngineQueryError(str(exc)) from exc


def delete_graph() -> None:
    try:
        _get_client().select_graph(current_graph()).delete()
    except ResponseError:
        pass  # graph did not exist yet
    except (RedisConnectionError, RedisTimeoutError, OSError) as exc:
        _reset_client()
        raise EngineUnavailable(f"Cannot reach FalkorDB at {HOST}:{PORT} ({type(exc).__name__}).") from exc
