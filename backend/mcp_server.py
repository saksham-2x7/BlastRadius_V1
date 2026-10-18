"""BlastRadius MCP server (official `mcp` SDK). All tools are read-only.

Two ways to use it:
  * stdio (Claude Desktop, Cursor, ...):   .venv/bin/python mcp_server.py
  * streamable HTTP, mounted in FastAPI:   http://127.0.0.1:8000/mcp/   (send header X-Engine-Key if ENGINE_API_KEY is set)

Tool inputs are validated by Pydantic (types, ranges, regex patterns); outputs are typed Pydantic models, so clients
receive both a JSON schema and structured results.
"""
import config  # noqa: F401  (loads backend/.env for stdio runs; must stay the first import)
import os
from typing import Annotated

import anyio
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from pydantic import Field

import threat_tools as t

# FastMCP rejects requests whose Host header is not allow-listed (DNS-rebinding protection). Behind a proxy the Host is the
# public domain, so list it in MCP_ALLOWED_HOSTS (comma separated, e.g. "blastradius-api.up.railway.app").
_extra_hosts = [h.strip() for h in os.getenv("MCP_ALLOWED_HOSTS", "").split(",") if h.strip()]
SECURITY = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*", *_extra_hosts, *[f"{h}:*" for h in _extra_hosts]],
    allowed_origins=["http://127.0.0.1:*", "http://localhost:*", *[f"https://{h}" for h in _extra_hosts]],
)

READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)

mcp = FastMCP(
    "blastradius",
    instructions=(
        "BlastRadius analyses an infrastructure attack graph stored in FalkorDB. Call get_attack_paths first to see the "
        "attack paths and the findings ranked by how many paths they sit on, then get_vulnerability_context for one "
        "finding, and simulate_fix to preview a patch. These tools never change anything. CVSS, KEV and EPSS values are "
        "an illustrative snapshot, not live feeds."
    ),
    stateless_http=True,
    streamable_http_path="/",  # mounted at /mcp in FastAPI -> endpoint is /mcp/
    transport_security=SECURITY,
)


@mcp.tool(name="get_attack_paths", description=t.TOOLS["get_attack_paths"].description, annotations=READ_ONLY)
async def get_attack_paths(
    limit: Annotated[int, Field(ge=1, le=20, description="Maximum number of attack paths and ranked findings to return.")] = 10,
) -> t.AttackPathsOutput:
    return await anyio.to_thread.run_sync(t.get_attack_paths, limit)


@mcp.tool(name="get_vulnerability_context", description=t.TOOLS["get_vulnerability_context"].description, annotations=READ_ONLY)
async def get_vulnerability_context(
    cve_id: Annotated[t.FindingRef, Field(description="Finding id (e.g. 'F4') or CVE id (e.g. 'CVE-2014-0160').")],
) -> t.VulnContextOutput:
    return await anyio.to_thread.run_sync(t.get_vulnerability_context, cve_id)


@mcp.tool(name="simulate_fix", description=t.TOOLS["simulate_fix"].description, annotations=READ_ONLY)
async def simulate_fix(
    finding_id: Annotated[t.FindingRef, Field(description="Finding id (e.g. 'F4') or CVE id to simulate patching.")],
) -> t.SimulateOutput:
    return await anyio.to_thread.run_sync(t.simulate_fix, finding_id)


@mcp.tool(name="get_choke_points", description=t.TOOLS["get_choke_points"].description, annotations=READ_ONLY)
async def get_choke_points(
    limit: Annotated[int, Field(ge=1, le=10, description="How many hosts to return.")] = 5,
) -> t.ChokePointsOutput:
    return await anyio.to_thread.run_sync(t.get_choke_points, limit)


@mcp.tool(name="explain_attack_path", description=t.TOOLS["explain_attack_path"].description, annotations=READ_ONLY)
async def explain_attack_path(
    routes: Annotated[int, Field(ge=1, le=5, description="How many shortest routes to return.")] = 3,
) -> t.ExplainOutput:
    return await anyio.to_thread.run_sync(t.explain_attack_path, routes)


ACT = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False)


@mcp.tool(name="apply_safe_fix", description=t.TOOLS["apply_safe_fix"].description, annotations=ACT)
async def apply_safe_fix(
    finding_id: Annotated[t.FindingRef, Field(description="Finding id (e.g. 'F3') or CVE id to fix.")],
    reason: Annotated[str, Field(min_length=3, max_length=300, description="Why you are acting; stored in graph memory.")],
) -> t.ApplyOutput:
    return await anyio.to_thread.run_sync(t.apply_safe_fix, finding_id, reason)


@mcp.tool(name="recall_agent_memory", description=t.TOOLS["recall_agent_memory"].description, annotations=READ_ONLY)
async def recall_agent_memory(
    limit: Annotated[int, Field(ge=1, le=25, description="How many past actions to return.")] = 10,
) -> t.RecallOutput:
    return await anyio.to_thread.run_sync(t.recall_agent_memory, limit)


@mcp.tool(name="draft_fix_ticket", description=t.TOOLS["draft_fix_ticket"].description, annotations=READ_ONLY)
async def draft_fix_ticket(
    finding_id: Annotated[t.FindingRef, Field(description="Finding id (e.g. 'F4') or CVE id to write the ticket for.")],
    format: Annotated[str, Field(pattern="^(github|jira)$", description="'github' or 'jira'.")] = "github",
) -> t.TicketOutput:
    return await anyio.to_thread.run_sync(t.draft_fix_ticket, finding_id, format)


@mcp.tool(name="file_github_issue", description=t.TOOLS["file_github_issue"].description, annotations=ACT)
async def file_github_issue(
    finding_id: Annotated[t.FindingRef, Field(description="Finding id (e.g. 'F4') or CVE id to file an issue for.")],
) -> t.FileOutput:
    return await anyio.to_thread.run_sync(t.file_github_issue, finding_id)


@mcp.tool(name="escalate_to_human", description=t.TOOLS["escalate_to_human"].description, annotations=ACT)
async def escalate_to_human(
    finding_id: Annotated[t.FindingRef, Field(description="Finding id (e.g. 'F4') or CVE id that needs a human.")],
    reason: Annotated[str, Field(min_length=3, max_length=300, description="Why a human is needed; stored on the request.")],
) -> t.EscalateOutput:
    return await anyio.to_thread.run_sync(t.escalate_to_human, finding_id, reason)


@mcp.tool(name="list_pending_approvals", description=t.TOOLS["list_pending_approvals"].description, annotations=READ_ONLY)
async def list_pending_approvals(
    limit: Annotated[int, Field(ge=1, le=25, description="How many requests to return.")] = 10,
) -> t.PendingOutput:
    return await anyio.to_thread.run_sync(t.list_pending_approvals, limit)


@mcp.tool(name="get_blast_zone", description=t.TOOLS["get_blast_zone"].description, annotations=READ_ONLY)
async def get_blast_zone(
    host: Annotated[t.HostRef, Field(description="Host id, e.g. 'api-gateway'.")],
) -> t.BlastZoneOutput:
    return await anyio.to_thread.run_sync(t.get_blast_zone, host)


if __name__ == "__main__":
    mcp.run()  # stdio
