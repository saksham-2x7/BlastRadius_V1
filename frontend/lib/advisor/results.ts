/** Types mirroring the engine's Pydantic output models (backend/threat_tools.py). */

export interface RankedFinding {
  finding_id: string;
  cve_id: string;
  host: string;
  cvss: number;
  epss: number;
  kev: boolean;
  exploitable: boolean;
  patched: boolean;
  attack_paths: number;
  tier: string;
  reason: string;
}

export interface AttackPathsResult {
  total_attack_paths: number;
  paths: string[][];
  choke_points: { host: string; attack_paths: number }[];
  top_findings: RankedFinding[];
  patched_count: number;
}

export interface ContextResult {
  finding_id: string;
  cve_id: string;
  product: string | null;
  summary: string | null;
  host: string;
  host_software: string | null;
  cvss: number;
  epss: number;
  epss_percent: number;
  kev: boolean;
  tier: string;
  tier_reason: string;
  blast_radius: { attack_paths_through_host: number; total_attack_paths: number; reaches_crown_jewel: boolean };
  priority_note: string;
}

export interface SimulateResult {
  finding_id: string;
  cve_id: string;
  host: string;
  paths_before: number;
  paths_after: number;
  paths_eliminated: number;
  eliminated_paths: string[][];
  remaining_paths: string[][];
  verdict: string;
}

export interface ChokeResult {
  method: string;
  ranking: { host: string; betweenness: number; pagerank: number; attack_paths: number; is_choke_point: boolean; software: string | null }[];
  note: string;
}

export interface ExplainResult {
  method: string;
  shortest_hops: number;
  tied_routes: number;
  routes: { hops: number; route: string[]; still_exploitable: boolean }[];
  note: string;
}

export interface ApplyResult {
  finding_id: string;
  cve_id: string;
  host: string;
  decision: "applied" | "needs_human_approval" | "not_applicable";
  paths_before: number;
  paths_after: number;
  message: string;
  memory_id: string;
}

export interface RecallResult {
  actions: { id: string; ts: number; tool: string; finding_id: string; host: string; decision: string; rationale: string; paths_before: number; paths_after: number }[];
  note: string;
}

export interface TicketResult {
  finding_id: string;
  format: string;
  title: string;
  priority: string;
  labels: string[];
  assignee_hint: string;
  requires_human_approval: boolean;
  body_markdown: string;
  memory_id: string;
}

export interface FileResult {
  finding_id: string;
  filed: boolean;
  url: string | null;
  number: number | null;
  message: string;
  title: string;
  memory_id: string;
}
