import "server-only";
import { EngineError } from "@/lib/engine";
import type { ApplyResult, AttackPathsResult, ChokeResult, ContextResult, ExplainResult, RecallResult, SimulateResult, TicketResult, FileResult, EscalateResult, PendingResult, BlastZoneResult, PlaybookResult } from "./results";

/** One tool as declared by the MCP server (JSON Schema generated from the Pydantic models). */
export interface ToolSpec {
  name: string;
  description: string;
  input_schema: Record<string, unknown>;
}

/** Where a provider gets its tools from. Today that is the MCP server (see ./mcp.ts). */
export interface ToolSource {
  list(): Promise<ToolSpec[]>;
  call(name: string, args: Record<string, unknown>): Promise<unknown>;
  close(): Promise<void>;
}

/** Human-readable one-liner shown in the panel after a tool finishes. */
export function summarize(name: string, result: unknown): string {
  switch (name) {
    case "get_attack_paths": {
      const r = result as AttackPathsResult;
      return `${r.total_attack_paths} attack paths · ${r.choke_points.length} choke point${r.choke_points.length === 1 ? "" : "s"} · ${r.top_findings.length} ranked findings`;
    }
    case "get_vulnerability_context": {
      const r = result as ContextResult;
      return `${r.finding_id} ${r.cve_id} · ${r.kev ? "KEV · " : ""}EPSS ${r.epss_percent}% · ${r.blast_radius.attack_paths_through_host} paths through ${r.host}`;
    }
    case "simulate_fix": {
      const r = result as SimulateResult;
      return `${r.finding_id}: ${r.paths_before} → ${r.paths_after} paths (−${r.paths_eliminated}) · read-only`;
    }
    case "get_choke_points": {
      const r = result as ChokeResult;
      const chokes = r.ranking.filter((h) => h.is_choke_point).map((h) => h.host);
      return `${chokes.length ? `choke point: ${chokes.join(", ")}` : "no choke point"} · top exposure: ${r.ranking.slice(0, 3).map((h) => `${h.host} (${h.attack_paths} paths, betweenness ${h.betweenness})`).join(" · ")}`;
    }
    case "explain_attack_path": {
      const r = result as ExplainResult;
      return r.routes.length ? `${r.tied_routes} route${r.tied_routes === 1 ? "" : "s"} tie at ${r.shortest_hops} hops · showing ${r.routes.length}, all still exploitable` : "no exploitable route remains";
    }
    case "apply_safe_fix": {
      const r = result as ApplyResult;
      return r.decision === "applied" ? `${r.finding_id} applied · paths ${r.paths_before} → ${r.paths_after} · saved to memory` : `${r.finding_id}: ${r.decision.replace(/_/g, " ")} · saved to memory`;
    }
    case "draft_fix_ticket": {
      const r = result as TicketResult;
      return `${r.priority} ${r.format} ticket drafted for ${r.finding_id}${r.requires_human_approval ? " · needs approval" : ""} · saved to memory`;
    }
    case "file_github_issue": {
      const r = result as FileResult;
      return r.filed ? `GitHub issue filed: ${r.url} · saved to memory` : `not filed (${r.message.split(".")[0]}) · saved to memory`;
    }
    case "escalate_to_human": {
      const r = result as EscalateResult;
      return r.status === "not_needed" ? `${r.finding_id}: no escalation needed` : `${r.finding_id}: approval request ${r.request_id} ${r.status === "already_pending" ? "already waiting" : "open"}${r.notified ? " · team notified" : ""}`;
    }
    case "list_pending_approvals": {
      const r = result as PendingResult;
      return r.pending.length ? `${r.pending.length} waiting for a human: ${r.pending.map((p) => `${p.finding_id} (${p.host})`).join(", ")}` : "nothing waiting for approval";
    }
    case "get_blast_zone": {
      const r = result as BlastZoneResult;
      return `${r.host} reaches ${r.reachable.length} node${r.reachable.length === 1 ? "" : "s"}${r.reaches_crown_jewel ? " · crown jewel in reach" : " · no crown jewel"} (FalkorDB BFS)`;
    }
    case "generate_remediation_playbook": {
      const r = result as PlaybookResult;
      return `playbook for ${r.fixes.length} fix${r.fixes.length === 1 ? "" : "es"} · ${r.fixes.filter((f) => f.fixed_version).length} with a fixed version from OSV · changes no server`;
    }
    case "recall_agent_memory": {
      const r = result as RecallResult;
      return `${r.actions.length} past action${r.actions.length === 1 ? "" : "s"} recalled from the graph`;
    }
    default:
      return "done";
  }
}

export function toolErrorMessage(err: unknown): string {
  if (err instanceof EngineError) return err.info.message;
  return err instanceof Error ? err.message : "Tool call failed.";
}
