"""Agent memory: every decision the advisor agent takes is written to the graph and recalled in later sessions.

Stored in the accounts graph (not the sample graph), so "restore demo" never erases what the agent remembers.
Model:  (:Agent {name})-[:DID]->(:AgentAction {id, ts, tool, finding_id, host, decision, rationale, paths_before, paths_after, ws})
                                       -[:IN]->(:Workspace {id})
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
