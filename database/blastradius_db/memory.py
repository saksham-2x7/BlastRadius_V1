"""Agent memory: every decision the advisor agent takes is written to the graph and recalled in later sessions.

Stored in the accounts graph (not the sample graph), so "restore demo" never erases what the agent remembers.
Model:  (:Agent {name})-[:DID]->(:AgentAction {id, ts, tool, finding_id, host, decision, rationale, paths_before, paths_after, ws})
                                       -[:IN]->(:Workspace {id})
Approvals: when the agent refuses a high-risk fix it opens (:ApprovalRequest {status: pending}) in the same workspace; a human
approving the fix in the dashboard closes it. (:Agent)-[:REQUESTED]->(:ApprovalRequest)-[:IN]->(:Workspace)
Memory is per tenant: an action is stored against the workspace it was taken in (the shared sample, or one user's own graph),
and recall only returns that workspace's actions, so one user's agent never sees another's history.
"""
import time
import uuid
from typing import Any

from .db import ACCOUNTS_GRAPH, SAMPLE_GRAPH, current_graph, run

AGENT = "blastradius-advisor"


def remember(tool: str, finding_id: str, host: str, decision: str, rationale: str,
             paths_before: int = -1, paths_after: int = -1) -> str:
    action_id = f"ACT-{uuid.uuid4().hex[:6]}"
    run(
        """MERGE (a:Agent {name: $agent})
           MERGE (w:Workspace {id: $ws})
           CREATE (x:AgentAction {id: $id, ts: $ts, tool: $tool, finding_id: $fid, host: $host, decision: $decision,
                                  rationale: $why, paths_before: $pb, paths_after: $pa, ws: $ws})
           CREATE (a)-[:DID]->(x), (x)-[:IN]->(w)""",
        {"agent": AGENT, "ws": current_graph(), "id": action_id, "ts": int(time.time() * 1000), "tool": tool, "fid": finding_id, "host": host,
         "decision": decision, "why": rationale[:300], "pb": paths_before, "pa": paths_after},
        graph=ACCOUNTS_GRAPH,
    )
    return action_id


def recall(limit: int = 10) -> list[dict[str, Any]]:
    rows = run(
        """MATCH (:Agent {name: $agent})-[:DID]->(x:AgentAction)
           WHERE coalesce(x.ws, $sample) = $ws
           RETURN x.id, x.ts, x.tool, x.finding_id, x.host, x.decision, x.rationale, x.paths_before, x.paths_after
           ORDER BY x.ts DESC LIMIT $n""",
        {"agent": AGENT, "n": limit, "ws": current_graph(), "sample": SAMPLE_GRAPH},
        graph=ACCOUNTS_GRAPH,
    )
    keys = ("id", "ts", "tool", "finding_id", "host", "decision", "rationale", "paths_before", "paths_after")
    return [dict(zip(keys, r)) for r in rows]


def open_approval(finding_id: str, host: str, reason: str) -> tuple[str, bool]:
    """Open a pending approval request for a finding (once per finding per workspace). Returns (request id, newly created)."""
    ws = current_graph()
    rows = run("MATCH (r:ApprovalRequest {ws: $ws, finding_id: $fid, status: 'pending'}) RETURN r.id LIMIT 1",
               {"ws": ws, "fid": finding_id}, graph=ACCOUNTS_GRAPH)
    if rows:
        return rows[0][0], False
    rid = f"REQ-{uuid.uuid4().hex[:6]}"
    run(
        """MERGE (a:Agent {name: $agent})
           MERGE (w:Workspace {id: $ws})
           CREATE (r:ApprovalRequest {id: $id, ts: $ts, finding_id: $fid, host: $host, status: 'pending', reason: $why,
                                      ws: $ws, notified: false, resolved_by: '', resolved_ts: 0})
           CREATE (a)-[:REQUESTED]->(r), (r)-[:IN]->(w)""",
        {"agent": AGENT, "ws": ws, "id": rid, "ts": int(time.time() * 1000), "fid": finding_id, "host": host, "why": reason[:300]},
        graph=ACCOUNTS_GRAPH,
    )
    return rid, True


def resolve_approval(finding_id: str, by: str = "human") -> int:
    """A human approved the fix: close the matching pending request(s). Returns how many were closed."""
    rows = run(
        """MATCH (r:ApprovalRequest {ws: $ws, finding_id: $fid, status: 'pending'})
           SET r.status = 'approved', r.resolved_by = $by, r.resolved_ts = $ts RETURN count(r)""",
        {"ws": current_graph(), "fid": finding_id, "by": by, "ts": int(time.time() * 1000)}, graph=ACCOUNTS_GRAPH)
    return int(rows[0][0]) if rows else 0


def cancel_pending() -> int:
    """The workspace was restored or re-imported: pending requests no longer refer to anything real."""
    rows = run(
        """MATCH (r:ApprovalRequest {ws: $ws, status: 'pending'})
           SET r.status = 'cancelled', r.resolved_ts = $ts RETURN count(r)""",
        {"ws": current_graph(), "ts": int(time.time() * 1000)}, graph=ACCOUNTS_GRAPH)
    return int(rows[0][0]) if rows else 0


def pending_approvals(limit: int = 10) -> list[dict[str, Any]]:
    rows = run(
        """MATCH (r:ApprovalRequest {ws: $ws, status: 'pending'})
           RETURN r.id, r.ts, r.finding_id, r.host, r.reason ORDER BY r.ts DESC LIMIT $n""",
        {"ws": current_graph(), "n": limit}, graph=ACCOUNTS_GRAPH)
    return [dict(zip(("id", "ts", "finding_id", "host", "reason"), r)) for r in rows]


def claim_notification(request_id: str) -> bool:
    """Atomically mark a request as notified. True only for the caller that gets to send the team message."""
    rows = run("MATCH (r:ApprovalRequest {id: $id}) WHERE coalesce(r.notified, false) = false SET r.notified = true RETURN count(r)",
               {"id": request_id}, graph=ACCOUNTS_GRAPH)
    return bool(rows and rows[0][0])


def release_notification(request_id: str) -> None:
    """The message could not be sent: let a later escalation try again."""
    run("MATCH (r:ApprovalRequest {id: $id}) SET r.notified = false", {"id": request_id}, graph=ACCOUNTS_GRAPH)
