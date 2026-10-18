"""The three advisor tools, as strictly typed Pydantic models + plain functions.

Single source of truth: the MCP server (mcp_server.py), the REST dispatcher (POST /api/tools/{name}) and the
Next.js advisor all use these. Every tool is READ-ONLY: nothing here mutates the graph.
"""
import json
import os
import re
import time
import urllib.request
from typing import Annotated, Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field

import engine
import remediation
import segmentation
from blastradius_db import memory
from blastradius_db.db import run

# --------------------------------------------------------------------------------------------- shared types
# ECMAScript-compatible pattern (no inline flags) so any MCP client can validate it too.
FindingRef = Annotated[
    str,
    Field(
        min_length=2,
        max_length=20,
        pattern=r"^([Ff][0-9]{1,3}|[Cc][Vv][Ee]-[0-9]{4}-[0-9]{4,7})$",
        description="A finding id such as 'F4' or a CVE id such as 'CVE-2014-0160'.",
        examples=["F4", "CVE-2014-0160"],
    ),
]
Tier = Literal["auto", "approval", "monitor", "patched"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")  # unknown arguments are rejected, not silently ignored


class ToolNotFound(Exception):
    """The referenced finding does not exist (mapped to HTTP 404 / an MCP tool error)."""


# --------------------------------------------------------------------------------------------- inputs
class AttackPathsInput(_Strict):
    limit: int = Field(default=10, ge=1, le=20, description="Maximum number of attack paths and ranked findings to return.")


class ContextInput(_Strict):
    cve_id: FindingRef


class SimulateInput(_Strict):
    finding_id: FindingRef


# --------------------------------------------------------------------------------------------- outputs
class HostExposure(BaseModel):
    host: str
    software: str | None
    role: str | None
    attack_paths: int = Field(ge=0, description="How many attack paths run through this host.")
    choke_point: bool = Field(description="True if this host sits on the most attack paths (fix here first).")
    kev_findings: list[str] = Field(description="Unpatched CISA-KEV findings on this host.")


class RankedFinding(BaseModel):
    finding_id: str
    cve_id: str
    host: str
    cvss: float = Field(ge=0, le=10)
    epss: float = Field(ge=0, le=1, description="Exploit Prediction Scoring System probability (0-1). Illustrative snapshot.")
    kev: bool = Field(description="Listed in the CISA Known Exploited Vulnerabilities catalog (illustrative snapshot).")
    exploitable: bool
    patched: bool
    attack_paths: int = Field(ge=0)
    tier: Tier
    reason: str


class AttackPathsOutput(BaseModel):
    total_attack_paths: int = Field(ge=0)
    paths: list[list[str]] = Field(description="Internet -> crown jewel routes through still-exploitable hosts.")
    choke_points: list[HostExposure]
    most_exposed_hosts: list[HostExposure]
    top_findings: list[RankedFinding] = Field(description="Findings ranked by attack paths (not by CVSS).")
    patched_count: int
    data_note: str


class BlastRadius(BaseModel):
    attack_paths_through_host: int = Field(ge=0)
    total_attack_paths: int = Field(ge=0)
    downstream_hosts: list[str] = Field(description="Hosts an attacker on this host can reach (up to 6 hops).")
    reaches_crown_jewel: bool
    is_choke_point: bool
    example_paths: list[list[str]]


class VulnContextOutput(BaseModel):
    finding_id: str
    cve_id: str
    product: str | None
    summary: str | None
    host: str
    host_software: str | None
    cvss: float = Field(ge=0, le=10)
    epss: float = Field(ge=0, le=1)
    epss_percent: float = Field(ge=0, le=100)
    kev: bool
    exploitable: bool
    patched: bool
    tier: Tier
    tier_reason: str
    blast_radius: BlastRadius
    priority_note: str
    data_note: str


class SimulateOutput(BaseModel):
    finding_id: str
    cve_id: str
    host: str
    already_patched: bool
    paths_before: int = Field(ge=0)
    paths_after: int = Field(ge=0)
    paths_eliminated: int = Field(ge=0)
    eliminated_paths: list[list[str]]
    remaining_paths: list[list[str]]
    verdict: str
    read_only: Literal[True] = True


# --------------------------------------------------------------------------------------------- helpers
# Same query as engine.ATTACK_PATHS, but treats findings in $sim as patched. Read-only.
SIM_PATHS = """
MATCH p = (:Internet)-[:CAN_REACH*1..6]->(d:DataStore {crown: true})
WHERE all(n IN nodes(p) WHERE n:Internet OR n:DataStore OR any(f IN n.xf WHERE NOT f IN $sim))
RETURN [n IN nodes(p) | n.id] AS path
"""


def _resolve(scan: dict[str, Any], ref: str) -> dict[str, Any]:
    key = ref.strip().upper()
    for f in scan["findings"]:
        if f["id"].upper() == key or f["cve"].upper() == key:
            return f
    raise ToolNotFound(f"No finding matches '{ref}'. Call get_attack_paths to list valid finding and CVE ids.")


def _ranked(f: dict[str, Any]) -> RankedFinding:
    return RankedFinding(
        finding_id=f["id"], cve_id=f["cve"], host=f["host"], cvss=f["cvss"], epss=f["epss"], kev=f["kev"],
        exploitable=f["exploitable"], patched=f["patched"], attack_paths=f["paths"], tier=f["tier"], reason=f["reason"],
    )


def _exposures(scan: dict[str, Any]) -> list[HostExposure]:
    kev_by_host: dict[str, list[str]] = {}
    for f in scan["findings"]:
        if f["kev"] and not f["patched"]:
            kev_by_host.setdefault(f["host"], []).append(f["id"])
    hosts = [n for n in scan["nodes"] if n["kind"] == "host" and n["paths"] > 0]
    hosts.sort(key=lambda n: -n["paths"])
    return [
        HostExposure(host=n["id"], software=n.get("software"), role=n.get("role"), attack_paths=n["paths"],
                     choke_point=n["choke"], kev_findings=kev_by_host.get(n["id"], []))
        for n in hosts
    ]


# --------------------------------------------------------------------------------------------- tools
def get_attack_paths(limit: int = 10) -> AttackPathsOutput:
    scan = engine.scan()
    exposures = _exposures(scan)
    return AttackPathsOutput(
        total_attack_paths=scan["summary"]["paths"],
        paths=scan["paths"][:limit],
        choke_points=[e for e in exposures if e.choke_point],
        most_exposed_hosts=exposures[:5],
        top_findings=[_ranked(f) for f in scan["findings"][:limit]],
        patched_count=scan["summary"]["patched"],
        data_note=scan["data_notice"],
    )


def get_vulnerability_context(cve_id: str) -> VulnContextOutput:
    scan = engine.scan()
    f = _resolve(scan, cve_id)
    host = next(n for n in scan["nodes"] if n["id"] == f["host"] and n["kind"] == "host")
    downstream = [r[0] for r in run(
        "MATCH (h:Host {id: $h})-[:CAN_REACH*1..6]->(d) RETURN DISTINCT d.id", {"h": f["host"]}
    )]
    crown = {n["id"] for n in scan["nodes"] if n["crown"]}
    blast = BlastRadius(
        attack_paths_through_host=host["paths"],
        total_attack_paths=scan["summary"]["paths"],
        downstream_hosts=sorted(downstream),
        reaches_crown_jewel=bool(crown & set(downstream)),
        is_choke_point=host["choke"],
        example_paths=[p for p in scan["paths"] if f["host"] in p][:3],
    )

    notes: list[str] = []
    if f["patched"]:
        notes.append("Already patched.")
    else:
        if f["kev"]:
            notes.append("Listed in CISA KEV: exploitation in the wild is confirmed.")
        if f["epss"] >= 0.5:
            notes.append(f"EPSS {f['epss'] * 100:.0f}%: very likely to be exploited soon.")
        if host["paths"]:
            notes.append(f"Sits on {host['paths']} of {scan['summary']['paths']} attack paths to a crown jewel.")
        else:
            notes.append("Not on any attack path to a crown jewel right now, so lower priority" +
                         (f" despite CVSS {f['cvss']}." if f["cvss"] >= 9 else "."))
        if host["choke"]:
            notes.append("This host is the choke point: fixing it cuts the most paths.")
    return VulnContextOutput(
        finding_id=f["id"], cve_id=f["cve"], product=f.get("product"), summary=f.get("summary"), host=f["host"],
        host_software=host.get("software"), cvss=f["cvss"], epss=f["epss"], epss_percent=round(f["epss"] * 100, 1),
        kev=f["kev"], exploitable=f["exploitable"], patched=f["patched"], tier=f["tier"], tier_reason=f["reason"],
        blast_radius=blast, priority_note=" ".join(notes), data_note=scan["data_notice"],
    )


def simulate_fix(finding_id: str) -> SimulateOutput:
    """Read-only what-if: recompute attack paths as if this finding were patched. Nothing is written."""
    scan = engine.scan()
    f = _resolve(scan, finding_id)
    before = scan["paths"]
    after = [r[0] for r in run(SIM_PATHS, {"sim": [f["id"]]})]
    gone = [p for p in before if p not in after]
    if f["patched"]:
        verdict = f"{f['id']} is already patched; simulating it changes nothing."
    elif not f["exploitable"]:
        verdict = f"{f['id']} is not exploitable (not in KEV, EPSS below 10%), so patching it removes no attack paths."
    elif not gone:
        verdict = f"Patching {f['id']} on {f['host']} would not remove any attack path."
    else:
        verdict = (f"Patching {f['id']} on {f['host']} would remove {len(gone)} of {len(before)} attack paths "
                   f"({len(before)} -> {len(after)}).")
    return SimulateOutput(
        finding_id=f["id"], cve_id=f["cve"], host=f["host"], already_patched=f["patched"], paths_before=len(before),
        paths_after=len(after), paths_eliminated=len(gone), eliminated_paths=gone, remaining_paths=after, verdict=verdict,
    )


# --------------------------------------------------------------------------------------------- graph-algorithm + agent tools
class ChokeInput(_Strict):
    limit: int = Field(default=5, ge=1, le=10, description="How many hosts to return.")


class ChokeHost(BaseModel):
    host: str
    betweenness: float = Field(description="FalkorDB algo.betweenness score over the CAN_REACH network (higher = more routes pass through).")
    pagerank: float = Field(default=0.0, description="FalkorDB algo.pageRank score: how much of the network's reachability flows into this host.")
    attack_paths: int = Field(ge=0, description="Live internet-to-crown-jewel paths through this host.")
    is_choke_point: bool = Field(description="True only for the host(s) carrying the MOST live attack paths (the dashboard marks exactly these). Other rows are high-exposure hosts, not choke points.")
    software: str | None


class ChokePointsOutput(BaseModel):
    method: str
    ranking: list[ChokeHost]
    note: str


class ExplainInput(_Strict):
    routes: int = Field(default=3, ge=1, le=5, description="How many shortest routes to return.")


class Route(BaseModel):
    hops: int
    route: list[str]
    still_exploitable: bool = Field(description="True if every host on this route still has an unpatched exploitable finding.")


class ExplainOutput(BaseModel):
    method: str
    shortest_hops: int = Field(ge=0, description="Length of the shortest route that is still exploitable (0 if none remains).")
    tied_routes: int = Field(ge=0, description="How many routes share that shortest length. Ties are normal; routes shows the most exposed ones.")
    routes: list[Route]
    note: str


class ApplyInput(_Strict):
    finding_id: FindingRef
    reason: str = Field(min_length=3, max_length=300, description="Why you are acting. Stored in the agent's graph memory.")


class ApplyOutput(BaseModel):
    finding_id: str
    cve_id: str
    host: str
    decision: Literal["applied", "needs_human_approval", "not_applicable"]
    paths_before: int = Field(ge=0)
    paths_after: int = Field(ge=0)
    message: str
    memory_id: str


class FileInput(_Strict):
    finding_id: FindingRef


class FileOutput(BaseModel):
    finding_id: str
    filed: bool
    url: str | None
    number: int | None
    message: str
    title: str
    memory_id: str


class RecallInput(_Strict):
    limit: int = Field(default=10, ge=1, le=25, description="How many past actions to return, newest first.")


class PastAction(BaseModel):
    id: str
    ts: int
    tool: str
    finding_id: str
    host: str
    decision: str
    rationale: str
    paths_before: int
    paths_after: int


class RecallOutput(BaseModel):
    actions: list[PastAction]
    note: str


class TicketInput(_Strict):
    finding_id: FindingRef
    format: Literal["github", "jira"] = Field(default="github", description="Which tracker the ticket is written for.")


class TicketOutput(BaseModel):
    finding_id: str
    format: str
    title: str
    priority: str
    labels: list[str]
    assignee_hint: str
    requires_human_approval: bool
    body_markdown: str = Field(description="Ready to paste into the tracker.")
    memory_id: str


def _proposed_change(f: dict[str, Any], host: dict[str, Any]) -> list[str]:
    """The concrete fix for a ticket: the fixed version from OSV when it knows one, otherwise a clearly generic instruction."""
    try:
        fx = remediation.best_fix(remediation.fixed_versions(f["cve"]), f.get("product"))
    except Exception:
        fx = None
    where = f"on `{f['host']}` ({host.get('software') or 'unknown'})"
    if not fx:
        return [f"Upgrade or reconfigure {f['product'] or 'the affected component'} {where} to a fixed version (OSV lists none for {f['cve']}; check the vendor advisory)."]
    out = [f"Upgrade **{fx['package']}** to **>= {fx['fixed']}** ({fx['ecosystem']}) {where}. Source: OSV {fx['source']}."]
    if fx.get("also_fixed_in"):
        out.append(f"Older release branches are fixed in {fx['also_fixed_in']}; the newest is the safe choice.")
    return out


def draft_fix_ticket(finding_id: str, format: str = "github") -> TicketOutput:
    """Turn a finding into a ready-to-file ticket, with graph evidence and the simulated impact. Writes nothing to any
    external system; the draft is logged in the agent's graph memory."""
    scan = engine.scan()
    f = _resolve(scan, finding_id)
    host = next(n for n in scan["nodes"] if n["id"] == f["host"] and n["kind"] == "host")
    sim = simulate_fix(f["id"])
    routes = [p for p in scan["paths"] if f["host"] in p][:3]
    if f["patched"]:
        prio = "P4 (done)"
    elif f["paths"] > 0 and f["kev"]:
        prio = "P1"
    elif f["paths"] > 0:
        prio = "P2"
    else:
        prio = "P3"
    approval = f["tier"] == "approval"
    title = f"[{prio}] Patch {f['cve']} on {f['host']} ({f['product'] or 'component'}): cuts {sim.paths_eliminated} attack path(s)"
    lines = [
        f"## {f['cve']} on `{f['host']}`",
        f"{f['product'] or ''}: {f['summary'] or ''}".strip(": "),
        "",
        "### Why this matters (from the attack graph)",
        f"- Sits on **{f['paths']} of {scan['summary']['paths']}** attack paths from the internet to a crown jewel" + (" and is the choke point." if host["choke"] else "."),
        f"- CISA KEV: **{'yes (exploited in the wild)' if f['kev'] else 'no'}** · EPSS **{f['epss'] * 100:.0f}%** · CVSS {f['cvss']}",
        f"- Autonomy tier: **{f['tier']}** ({f['reason']})",
        "",
        "### Simulated impact (read-only what-if)",
        f"- {sim.verdict}",
        *[f"- Route removed: `{' -> '.join(p)}`" for p in sim.eliminated_paths[:3]],
        *([""] + ["### Example routes through this host"] + [f"- `{' -> '.join(p)}`" for p in routes] if routes else []),
        "",
        "### Proposed change",
        *_proposed_change(f, host),
        f"Rollback: restore the previous package version / config snapshot for {f['cve']} on {f['host']}.",
        "",
        "**Needs human approval before applying.**" if approval else "Low blast radius: safe to apply automatically.",
        "",
        f"_Drafted by the BlastRadius agent from FalkorDB graph evidence. {scan['data_notice']}_",
    ]
    owner = host.get("role") or "service owner"
    mid = memory.remember("draft_fix_ticket", f["id"], f["host"], "ticket_drafted", f"{format} ticket, priority {prio}", scan["summary"]["paths"], sim.paths_after)
    return TicketOutput(
        finding_id=f["id"], format=format, title=title, priority=prio,
        labels=["security", "attack-path", *(["kev"] if f["kev"] else []), *(["needs-approval"] if approval else [])],
        assignee_hint=f"owner of: {owner}", requires_human_approval=approval, body_markdown="\n".join(lines), memory_id=mid,
    )


BETWEENNESS = """
CALL algo.betweenness({nodeLabels: ['Internet', 'Host', 'DataStore'], relationshipTypes: ['CAN_REACH']})
YIELD node, score RETURN node.id, score
"""
PAGERANK = """
CALL algo.pageRank('Host', 'CAN_REACH') YIELD node, score RETURN node.id, score
"""
SHORTEST = """
MATCH (s:Internet), (t:DataStore {crown: true})
CALL algo.SPpaths({sourceNode: s, targetNode: t, relationshipTypes: ['CAN_REACH'], pathCount: $n})
YIELD path RETURN [n IN nodes(path) | n.id]
"""


def get_choke_points(limit: int = 5) -> ChokePointsOutput:
    """Rank hosts with FalkorDB's betweenness-centrality algorithm, then join with live attack-path counts."""
    scan = engine.scan()
    info = {n["id"]: n for n in scan["nodes"] if n["kind"] == "host"}
    scores = [(r[0], float(r[1])) for r in run(BETWEENNESS) if r[0] in info]
    # Live attack paths decide the order (deterministic, and what a fix actually cuts); FalkorDB's centrality scores are the
    # structural signal shown beside it and the tie-breaker. Scores can differ slightly between FalkorDB versions.
    scores.sort(key=lambda x: (-info[x[0]]["paths"], -x[1]))
    try:
        pr = {r[0]: float(r[1]) for r in run(PAGERANK)}
    except Exception:  # an algorithm hiccup must never break the tool
        pr = {}
    ranking = [ChokeHost(host=h, betweenness=round(sc, 3), pagerank=round(pr.get(h, 0.0), 3), attack_paths=info[h]["paths"],
                         is_choke_point=bool(info[h]["choke"]), software=info[h].get("software"))
               for h, sc in scores[:limit]]
    return ChokePointsOutput(
        method="Ranked by live attack paths; FalkorDB algo.betweenness and algo.pageRank on the CAN_REACH graph give the structural centrality",
        ranking=ranking,
        note="Only rows with is_choke_point=true are choke points (the host(s) on the most live attack paths); the other rows are "
             "high-exposure hosts ranked by live attack paths, with betweenness and PageRank showing how central each host is. "
             "A host with high centrality but 0 attack paths is structurally central but not currently exploitable.",
    )


def explain_attack_path(routes: int = 3) -> ExplainOutput:
    """Shortest STILL-EXPLOITABLE routes from the internet to the crown jewel. Candidates come from FalkorDB's k-shortest-path
    algorithm (algo.SPpaths) and are filtered to routes whose every hop still carries an unpatched exploitable finding, so a
    route you already cut is never shown. Equal-length routes tie; they are ordered by how exposed their hosts are, then by
    name, so the answer is deterministic."""
    scan = engine.scan()
    live = [tuple(p) for p in scan["paths"]]
    live_set = set(live)
    load = {n["id"]: n["paths"] for n in scan["nodes"]}
    cands = [tuple(r[0]) for r in run(SHORTEST, {"n": 12})]
    pool = [p for p in cands if p in live_set] or live  # fall back to the live attack paths if none of the k candidates is live
    method = "FalkorDB algo.SPpaths (k shortest) filtered to routes that are still exploitable"
    if not pool:
        return ExplainOutput(method=method, shortest_hops=0, tied_routes=0, routes=[],
                             note="No attack route to a crown jewel remains: every route is already cut.")
    shortest = min(len(p) for p in pool)
    tied = [p for p in pool if len(p) == shortest]
    tied.sort(key=lambda p: (-sum(load.get(h, 0) for h in p[1:-1]), p))
    shown = tied[:routes]
    hops = shortest - 1
    return ExplainOutput(
        method=method, shortest_hops=hops, tied_routes=len(tied),
        routes=[Route(hops=hops, route=list(p), still_exploitable=True) for p in shown],
        note=(f"{len(tied)} still-exploitable route{'s' if len(tied) != 1 else ''} tie at {hops} hops; showing the {len(shown)} through the "
              "most exposed hosts. Equal length means no one of them is 'the' shortest."),
    )


_FILED: list[float] = []  # timestamps of issues filed by this process (simple hourly cap)
MAX_ISSUES_PER_HOUR = 5


def file_github_issue(finding_id: str) -> FileOutput:
    """File the drafted ticket as a REAL GitHub issue. Opt-in: needs GITHUB_TOKEN (issues:write) and GITHUB_REPO on the
    backend. Without them nothing is sent and the draft is returned. Capped per hour; every outcome is stored in memory."""
    token, repo = os.getenv("GITHUB_TOKEN"), os.getenv("GITHUB_REPO", "")
    draft = draft_fix_ticket(finding_id, "github")
    now = time.time()
    _FILED[:] = [t for t in _FILED if now - t < 3600]
    url = number = None
    if not token or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        filed, msg = False, "GitHub filing is not configured on this deployment (set GITHUB_TOKEN and GITHUB_REPO). Nothing was sent; the draft is ready to paste."
    elif len(_FILED) >= MAX_ISSUES_PER_HOUR:
        filed, msg = False, f"Rate limit: at most {MAX_ISSUES_PER_HOUR} issues per hour. Nothing was sent."
    else:
        try:
            req = urllib.request.Request(
                f"https://api.github.com/repos/{repo}/issues", method="POST",
                data=json.dumps({"title": draft.title, "body": draft.body_markdown, "labels": draft.labels}).encode(),
                headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                         "Content-Type": "application/json", "User-Agent": "blastradius-agent"})
            with urllib.request.urlopen(req, timeout=15) as r:  # noqa: S310 (fixed https GitHub API host)
                data = json.loads(r.read())
            url, number = data.get("html_url"), data.get("number")
            _FILED.append(now)
            filed, msg = True, f"Filed {url}"
        except Exception as exc:  # network, auth or permission problem: report it, never crash the agent
            filed, msg = False, f"GitHub rejected or could not be reached ({type(exc).__name__}). Nothing was filed."
    mid = memory.remember("file_github_issue", draft.finding_id, "-", "ticket_filed" if filed else "ticket_not_filed",
                          url or msg, -1, -1)
    return FileOutput(finding_id=draft.finding_id, filed=filed, url=url, number=number, message=msg, title=draft.title,
                      memory_id=mid)


def apply_safe_fix(finding_id: str, reason: str) -> ApplyOutput:
    """The agent ACTS, within hard limits: only auto-tier findings are applied. The tier is decided by graph facts in
    engine._tier (never by the model), and every decision, including refusals, is written to the agent's graph memory."""
    scan = engine.scan()
    f = _resolve(scan, finding_id)
    before = scan["summary"]["paths"]
    after = before
    if f["patched"]:
        decision, msg = "not_applicable", f"{f['id']} is already patched."
    elif f["tier"] == "auto":
        try:
            res = engine.apply_fix(f["id"], "auto")
            after = res["paths_after"]
            decision, msg = "applied", f"Patched {f['cve']} on {f['host']}: attack paths {before} -> {after}. A rollback note was stored."
        except engine.FixError as exc:
            decision, msg = "not_applicable", exc.message
    elif f["tier"] == "approval":
        decision = "needs_human_approval"
        rid, _ = memory.open_approval(f["id"], f["host"], reason)
        msg = (f"{f['id']} is high-risk ({f['reason']}). I will not apply it myself: approval request {rid} is open and a human "
               "must approve it in the Fix queue.")
    else:
        decision, msg = "not_applicable", f"{f['id']} is not on any attack path ({f['reason']}); nothing to do right now."
    mid = memory.remember("apply_safe_fix", f["id"], f["host"], decision, reason, before, after)
    return ApplyOutput(finding_id=f["id"], cve_id=f["cve"], host=f["host"], decision=decision, paths_before=before,
                       paths_after=after, message=msg, memory_id=mid)


def recall_agent_memory(limit: int = 10) -> RecallOutput:
    rows = memory.recall(limit)
    return RecallOutput(
        actions=[PastAction(**r) for r in rows],
        note="Stored in FalkorDB as (:Agent)-[:DID]->(:AgentAction); it persists across chats and across 'restore demo'.",
    )


# --------------------------------------------------------------------------------------------- human-in-the-loop + blast zone
HostRef = Annotated[str, Field(min_length=1, max_length=40, pattern=r"^[A-Za-z0-9_.-]+$", description="A host id such as 'api-gateway'.")]


class EscalateInput(_Strict):
    finding_id: FindingRef
    reason: str = Field(min_length=3, max_length=300, description="Why a human is needed. Stored on the approval request.")


class EscalateOutput(BaseModel):
    finding_id: str
    cve_id: str
    host: str
    status: Literal["requested", "already_pending", "not_needed"]
    notified: bool = Field(description="True if a message was posted to the team's webhook (opt-in, rate limited).")
    request_id: str | None
    message: str
    memory_id: str


class PendingInput(_Strict):
    limit: int = Field(default=10, ge=1, le=25)


class PendingApproval(BaseModel):
    id: str
    ts: int
    finding_id: str
    host: str
    reason: str


class PendingOutput(BaseModel):
    pending: list[PendingApproval]
    note: str


class BlastZoneInput(_Strict):
    host: HostRef


class ReachedNode(BaseModel):
    node: str
    kind: Literal["host", "datastore"]
    crown_jewel: bool
    attack_paths: int = Field(ge=0, description="Live internet-to-crown-jewel paths through this node.")


class BlastZoneOutput(BaseModel):
    host: str
    method: str
    reachable: list[ReachedNode]
    reaches_crown_jewel: bool
    on_attack_paths: int = Field(ge=0)
    note: str


BFS_REACH = """
MATCH (s:Host {id: $h})
CALL algo.BFS(s, 6, 'CAN_REACH') YIELD nodes
RETURN [n IN nodes | n.id]
"""
CYPHER_REACH = "MATCH (:Host {id: $h})-[:CAN_REACH*1..6]->(d) RETURN DISTINCT d.id"

_NOTIFIED: list[float] = []  # timestamps of webhook messages sent by this process
MAX_NOTIFY_PER_HOUR = 10


def _webhook_ready() -> bool:
    now = time.time()
    _NOTIFIED[:] = [t for t in _NOTIFIED if now - t < 3600]
    return os.getenv("ESCALATION_WEBHOOK_URL", "").startswith("https://") and len(_NOTIFIED) < MAX_NOTIFY_PER_HOUR


def _notify_webhook(text: str) -> bool:
    """Post to the team's webhook (Slack, Discord, Teams-compatible JSON). The URL comes only from the deployment's
    ESCALATION_WEBHOOK_URL, never from a user or the model; https only; capped per hour."""
    url = os.getenv("ESCALATION_WEBHOOK_URL", "")
    now = time.time()
    _NOTIFIED[:] = [t for t in _NOTIFIED if now - t < 3600]
    if not url.startswith("https://") or len(_NOTIFIED) >= MAX_NOTIFY_PER_HOUR:
        return False
    try:
        req = urllib.request.Request(url, method="POST", data=json.dumps({"text": text, "content": text}).encode(),
                                     headers={"Content-Type": "application/json", "User-Agent": "blastradius-agent"})
        with urllib.request.urlopen(req, timeout=8):  # noqa: S310 (https URL from deployment config)
            pass
        _NOTIFIED.append(now)
        return True
    except Exception:
        return False


def escalate_to_human(finding_id: str, reason: str) -> EscalateOutput:
    """ACT: hand a high-risk finding to a human. Opens an approval request in the graph (once per finding), and posts to the
    team's webhook if the deployment configured one. The dashboard's Approve button closes the request."""
    scan = engine.scan()
    f = _resolve(scan, finding_id)
    if f["patched"] or f["tier"] != "approval":
        why = "already patched" if f["patched"] else f"tier is '{f['tier']}', so it does not need a human"
        mid = memory.remember("escalate_to_human", f["id"], f["host"], "not_needed", reason, scan["summary"]["paths"], scan["summary"]["paths"])
        return EscalateOutput(finding_id=f["id"], cve_id=f["cve"], host=f["host"], status="not_needed", notified=False,
                              request_id=None, message=f"No escalation needed: {f['id']} is {why}.", memory_id=mid)
    sim = simulate_fix(f["id"])
    rid, created = memory.open_approval(f["id"], f["host"], reason)
    notified = False
    if _webhook_ready() and memory.claim_notification(rid):  # the first escalation of a request sends the team message
        notified = _notify_webhook(
            f"BlastRadius agent needs a human to approve {f['cve']} on {f['host']} ({f['reason']}). "
            f"Fixing it cuts {sim.paths_eliminated} of {sim.paths_before} attack paths. Approve it in the Fix queue. ({reason})")
        if not notified:
            memory.release_notification(rid)
    fresh = created or notified
    mid = memory.remember("escalate_to_human", f["id"], f["host"], "escalated" if fresh else "already_pending", reason,
                          sim.paths_before, sim.paths_after)
    msg = (f"Approval request {rid} is open for {f['id']} ({f['cve']} on {f['host']})" + ("; team notified." if notified else ".")
           if fresh else f"Approval request {rid} for {f['id']} was already waiting for a human.")
    return EscalateOutput(finding_id=f["id"], cve_id=f["cve"], host=f["host"], status="requested" if fresh else "already_pending",
                          notified=notified, request_id=rid, message=msg, memory_id=mid)


def list_pending_approvals(limit: int = 10) -> PendingOutput:
    rows = memory.pending_approvals(limit)
    return PendingOutput(
        pending=[PendingApproval(**r) for r in rows],
        note="Requests the agent opened for fixes it may not apply itself. A human approving the fix in the dashboard closes them.")


def get_blast_zone(host: str) -> BlastZoneOutput:
    """What an attacker can reach after compromising this host: FalkorDB's algo.BFS over CAN_REACH (6 levels)."""
    scan = engine.scan()
    info = {n["id"]: n for n in scan["nodes"] if n["kind"] in ("host", "datastore")}
    if host not in info or info[host]["kind"] != "host":
        raise ToolNotFound(f"No host '{host}'. Call get_attack_paths or get_choke_points to list host ids.")
    method = "FalkorDB algo.BFS over CAN_REACH, 6 levels"
    try:
        rows = run(BFS_REACH, {"h": host})
        ids = list(rows[0][0]) if rows else []
    except Exception:  # an older/newer FalkorDB without this call: same answer with a variable-length Cypher traversal
        ids = [r[0] for r in run(CYPHER_REACH, {"h": host})]
        method = "Cypher variable-length traversal over CAN_REACH, 6 hops (algo.BFS unavailable)"
    reached = [ReachedNode(node=i, kind=info[i]["kind"], crown_jewel=bool(info[i]["crown"]), attack_paths=info[i]["paths"])
               for i in dict.fromkeys(ids) if i in info and i != host]
    reached.sort(key=lambda r: (not r.crown_jewel, -r.attack_paths, r.node))
    crown = any(r.crown_jewel for r in reached)
    return BlastZoneOutput(
        host=host, method=method, reachable=reached, reaches_crown_jewel=crown, on_attack_paths=info[host]["paths"],
        note=(f"An attacker on {host} can reach {len(reached)} more node(s)" + (", including a crown jewel." if crown else "; none of them is a crown jewel."))
             + " Whether that is exploitable depends on the findings along the way (see on_attack_paths).")


# --------------------------------------------------------------------------------------------- remediation playbook
class PlaybookInput(_Strict):
    scope: Literal["applied", "open_on_paths"] = Field(
        default="applied", description="'applied': the fixes already applied or approved. 'open_on_paths': every unpatched finding on a live attack path.")


class PlaybookFix(BaseModel):
    finding_id: str
    cve_id: str
    host: str
    product: str | None
    mode: str
    ecosystem: str | None
    package: str | None
    fixed_version: str | None
    source: str | None


class PlaybookOutput(BaseModel):
    scope: str
    fixes: list[PlaybookFix]
    playbook_yaml: str = Field(description="Ansible playbook with fix and rollback tasks. Run it with --check --diff first.")
    note: str
    memory_id: str


def generate_remediation_playbook(scope: str = "applied") -> PlaybookOutput:
    """Turn decided fixes into a runnable Ansible playbook with fixed versions looked up live from OSV. Touches no server."""
    scan = engine.scan()
    by_id = {f["id"]: f for f in scan["findings"]}
    if scope == "applied":
        picked = [(h["finding_id"], h["mode"]) for h in scan["history"] if h["finding_id"] in by_id]
    else:
        picked = [(f["id"], "proposed") for f in scan["findings"] if not f["patched"] and f["paths"] > 0]
    rows: list[dict[str, Any]] = []
    for fid, mode in list(dict.fromkeys(picked))[:25]:
        f = by_id[fid]
        fx = remediation.best_fix(remediation.fixed_versions(f["cve"]), f.get("product"))
        rows.append({"finding_id": fid, "cve": f["cve"], "host": f["host"], "product": f.get("product"), "mode": mode, "fix": fx})
    yaml_text = remediation.build_playbook(rows)
    found = sum(1 for r in rows if r["fix"])
    mid = memory.remember("generate_remediation_playbook", "-", "-", "playbook_generated", f"scope={scope}, {len(rows)} fixes, {found} with a known fixed version",
                          scan["summary"]["paths"], scan["summary"]["paths"])
    return PlaybookOutput(
        scope=scope,
        fixes=[PlaybookFix(finding_id=r["finding_id"], cve_id=r["cve"], host=r["host"], product=r["product"], mode=r["mode"],
                           ecosystem=(r["fix"] or {}).get("ecosystem"), package=(r["fix"] or {}).get("package"),
                           fixed_version=(r["fix"] or {}).get("fixed"), source=(r["fix"] or {}).get("source")) for r in rows],
        playbook_yaml=yaml_text,
        note=(f"{len(rows)} fix(es), {found} with a fixed version from OSV." if rows else
              "No fixes to export yet: apply or approve a fix first, or use scope 'open_on_paths'.")
        + " BlastRadius changes no server; review the playbook and run it with --check --diff first.",
        memory_id=mid)


# --------------------------------------------------------------------------------------------- segmentation (min cut)
class CutInput(_Strict):
    pass


class CutEdge(BaseModel):
    source: str
    target: str
    attack_paths: int = Field(ge=0, description="Live attack paths that use this connection.")


class CutOutput(BaseModel):
    paths_now: int = Field(ge=0)
    cut: list[CutEdge]
    method: str
    structural_edge_disjoint_routes: int | None = Field(description="FalkorDB algo.maxFlow over the whole network: how many edge-disjoint routes exist (an upper bound on any cut).")
    note: str


MAXFLOW = """
MATCH (s:Internet)
MATCH (t:DataStore {crown: true})
WITH s, collect(t) AS ts
CALL algo.maxFlow({sourceNodes: [s], targetNodes: ts, relationshipTypes: ['CAN_REACH'], capacityProperty: 'cap'})
YIELD maxFlow RETURN maxFlow
"""


def suggest_network_cut() -> CutOutput:
    """The fewest connections to remove so no live attack path remains, an alternative to waiting for patches."""
    scan = engine.scan()
    paths = scan["paths"]
    cut = segmentation.min_cut(paths)
    use = {}
    for p in paths:
        for a, b in zip(p, p[1:]):
            use[(a, b)] = use.get((a, b), 0) + 1
    structural: int | None
    try:  # FalkorDB cross-check on the whole network; edges need a capacity, set once (idempotent)
        run("MATCH ()-[e:CAN_REACH]->() WHERE e.cap IS NULL SET e.cap = 1")
        rows = run(MAXFLOW)
        structural = int(rows[0][0]) if rows else 0
    except Exception:
        structural = None
    edges = [CutEdge(source=a, target=b, attack_paths=use.get((a, b), 0)) for a, b in cut]
    if not paths:
        note = "No live attack path exists, so no cut is needed."
    else:
        note = (f"Remove these {len(edges)} connection(s) (firewall or security-group rules) and none of the {len(paths)} live attack path(s) "
                "can reach a crown jewel. This is the minimum: no smaller set of connections does it. Patching can wait, but the "
                "connections may be needed by the business, so check before cutting.")
    return CutOutput(paths_now=len(paths), cut=edges, structural_edge_disjoint_routes=structural, note=note,
                     method="Minimum edge cut over the live attack paths (Edmonds-Karp); cross-checked with FalkorDB algo.maxFlow on the network")


# --------------------------------------------------------------------------------------------- registry
class ToolDef:
    def __init__(self, description: str, input_model: type[BaseModel], output_model: type[BaseModel],
                 call: Callable[[Any], BaseModel], read_only: bool = True):
        self.read_only = read_only
        self.description = description
        self.input_model = input_model
        self.output_model = output_model
        self.call = call


TOOLS: dict[str, ToolDef] = {
    "get_attack_paths": ToolDef(
        "Return the current attack paths (Internet to crown jewel), the choke points, the most exposed hosts and the "
        "findings ranked by how many attack paths they sit on. Start here to see what matters.",
        AttackPathsInput, AttackPathsOutput, lambda i: get_attack_paths(i.limit),
    ),
    "get_vulnerability_context": ToolDef(
        "Return the EPSS score, CISA-KEV status, CVSS, autonomy tier and blast radius of one finding, "
        "identified by finding id (e.g. 'F4') or CVE id (e.g. 'CVE-2014-0160').",
        ContextInput, VulnContextOutput, lambda i: get_vulnerability_context(i.cve_id),
    ),
    "simulate_fix": ToolDef(
        "Read-only what-if: how many attack paths would be eliminated if this finding were patched? "
        "Never changes anything; applying a fix is a separate, human-controlled action.",
        SimulateInput, SimulateOutput, lambda i: simulate_fix(i.finding_id),
    ),
    "get_choke_points": ToolDef(
        "Rank exposed hosts by live attack paths, with FalkorDB betweenness and PageRank centrality alongside. Only hosts "
        "with is_choke_point=true are choke points (the host(s) on the most live paths); call the rest high-exposure hosts. "
        "Use it to decide where one fix cuts the most routes.",
        ChokeInput, ChokePointsOutput, lambda i: get_choke_points(i.limit),
    ),
    "explain_attack_path": ToolDef(
        "Show the shortest routes from the internet to the crown jewel (FalkorDB shortest-path algorithm), so an answer "
        "can cite the exact path. Read-only.",
        ExplainInput, ExplainOutput, lambda i: explain_attack_path(i.routes),
    ),
    "apply_safe_fix": ToolDef(
        "ACT: apply a fix, but only if the graph classifies it as low-risk (tier 'auto'). High-risk findings are refused "
        "and need a human. Call it only when the user asks you to fix or clean up. Every decision is stored in graph memory.",
        ApplyInput, ApplyOutput, lambda i: apply_safe_fix(i.finding_id, i.reason), read_only=False,
    ),
    "recall_agent_memory": ToolDef(
        "Recall the agent's own past actions and decisions from the graph memory, newest first. Use it when asked what "
        "was done before or to avoid repeating work.",
        RecallInput, RecallOutput, lambda i: recall_agent_memory(i.limit),
    ),
    "draft_fix_ticket": ToolDef(
        "Draft a ready-to-file GitHub or Jira ticket for one finding, with graph evidence (attack paths, KEV, EPSS), the "
        "simulated impact and a rollback note. Writes to no external system; logged in graph memory.",
        TicketInput, TicketOutput, lambda i: draft_fix_ticket(i.finding_id, i.format),
    ),
    "file_github_issue": ToolDef(
        "ACT: file the drafted ticket as a real GitHub issue. Only when the user explicitly asks you to file or open an "
        "issue. Opt-in: does nothing unless the deployment has GitHub configured. Capped per hour; stored in graph memory.",
        FileInput, FileOutput, lambda i: file_github_issue(i.finding_id), read_only=False,
    ),
    "escalate_to_human": ToolDef(
        "ACT: hand a high-risk finding to a human. Opens an approval request in the graph and, if the team configured a "
        "webhook, notifies them. Use it after apply_safe_fix refuses a finding. The dashboard Approve button closes it.",
        EscalateInput, EscalateOutput, lambda i: escalate_to_human(i.finding_id, i.reason), read_only=False,
    ),
    "list_pending_approvals": ToolDef(
        "List the approval requests still waiting for a human (fixes the agent may not apply itself).",
        PendingInput, PendingOutput, lambda i: list_pending_approvals(i.limit),
    ),
    "get_blast_zone": ToolDef(
        "What can an attacker reach after compromising one host? Uses FalkorDB's breadth-first-search algorithm over "
        "reachability and says whether a crown jewel is in the zone. Read-only.",
        BlastZoneInput, BlastZoneOutput, lambda i: get_blast_zone(i.host),
    ),
    "generate_remediation_playbook": ToolDef(
        "Export decided fixes as a runnable Ansible playbook (with rollback), using fixed versions looked up live from OSV. "
        "The real-world handoff: BlastRadius changes no server itself. scope 'applied' = fixes already applied or approved.",
        PlaybookInput, PlaybookOutput, lambda i: generate_remediation_playbook(i.scope),
    ),
    "suggest_network_cut": ToolDef(
        "Network segmentation plan: the fewest connections to cut so no route from the internet reaches a crown jewel. An "
        "alternative to patching that a network team can do now. Uses a minimum cut over the live attack paths, cross-checked "
        "with FalkorDB's max-flow algorithm. Read-only: it changes nothing.",
        CutInput, CutOutput, lambda i: suggest_network_cut(),
    ),
}
