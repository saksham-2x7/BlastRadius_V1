/** Types + fetch helper for the Python/FalkorDB engine (backend/). Server-side only (reads BACKEND_URL). */

export type Tier = "auto" | "approval" | "monitor" | "patched";
export type NodeKind = "internet" | "host" | "datastore" | "vulnerability";

export interface Finding {
  id: string;
  cve: string;
  host: string;
  cvss: number;
  epss: number;
  kev: boolean;
  exploitable: boolean;
  patched: boolean;
  paths: number;
  tier: Tier;
  reason: string;
  product: string | null;
  summary: string | null;
}

export interface GraphNode {
  id: string;
  kind: NodeKind;
  crown: boolean;
  choke: boolean;
  paths: number;
  kev?: boolean; // host: has an unpatched CISA-KEV finding; vulnerability: is in KEV
  epss?: number; // vulnerability only (0-1)
  software?: string | null; // host only
  role?: string | null; // host only
  host?: string;
  cve?: string;
  cvss?: number;
  exploitable?: boolean;
  patched?: boolean;
}

export interface GraphEdge {
  source: string;
  target: string;
  type: "CAN_REACH" | "HAS_FINDING";
  hot: boolean;
}

export interface FixRecord {
  id: string;
  finding_id: string;
  cve: string;
  host: string;
  mode: "auto" | "approved";
  ts: number;
  rollback: string;
}

export interface Scan {
  summary: { paths: number; exploitable: number; auto: number; approval: number; monitor: number; patched: number; kev: number };
  paths: string[][];
  nodes: GraphNode[];
  edges: GraphEdge[];
  findings: Finding[];
  history: FixRecord[];
  data_notice: string;
  workspace?: "sample" | "own";
}

export interface FixResult {
  fixed: string;
  mode: "auto" | "approved";
  paths_before: number;
  paths_after: number;
  scan: Scan;
}

export interface AutoAllResult {
  applied: string[];
  paths_before: number;
  paths_after: number;
  scan: Scan;
}

/** Serializable error shown by the UI. */
export interface EngineErrorInfo {
  kind: "engine_unavailable" | "api_unreachable" | "rejected" | "unauthorized" | "upgrade_required" | "unknown";
  status: number;
  message: string;
  host?: string;
  port?: number;
}

export const BACKEND_URL = process.env.BACKEND_URL ?? "http://127.0.0.1:8000";

export class EngineError extends Error {
  info: EngineErrorInfo;
  constructor(info: EngineErrorInfo) {
    super(info.message);
    this.info = info;
  }
}

/** Parse an engine error response body into EngineErrorInfo. */
export function toErrorInfo(status: number, body: unknown): EngineErrorInfo {
  const b = (body ?? {}) as { error?: string; message?: string; host?: string; port?: number; detail?: unknown };
  if (b.error === "engine_unavailable") {
    return { kind: "engine_unavailable", status, message: b.message ?? "FalkorDB is unreachable.", host: b.host, port: b.port };
  }
  if (b.error === "upgrade_required") return { kind: "upgrade_required", status, message: b.message ?? "This feature needs the Pro plan." };
  if (status === 401 && typeof b.detail === "string") {
    return { kind: "unknown", status, message: "The engine rejected the request. Check that ENGINE_API_KEY matches in .env.local and backend/.env." };
  }
  if (status === 401) return { kind: "unauthorized", status, message: "Your session expired. Sign in again." };
  if (b.error === "fix_rejected") return { kind: "rejected", status, message: b.message ?? "Fix rejected." };
  if (status === 422) {
    const d = Array.isArray(b.detail) ? (b.detail[0] as { loc?: unknown[]; msg?: string } | undefined) : undefined;
    const where = (d?.loc ?? []).slice(1).join(".");
    return { kind: "rejected", status, message: d?.msg ? `Invalid input${where ? ` at ${where}` : ""}: ${d.msg.replace(/^Value error, /, "")}` : "That request was not valid. Refresh the page and try again." };
  }
  const detail = typeof b.detail === "string" ? b.detail : undefined;
  return { kind: "unknown", status, message: b.message ?? detail ?? `Engine returned HTTP ${status}.` };
}

export async function engineFetch<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${BACKEND_URL}${path}`, {
      ...init,
      cache: "no-store",
      signal: AbortSignal.timeout(10_000),
      headers: {
        "Content-Type": "application/json",
        ...(process.env.ENGINE_API_KEY ? { "X-Engine-Key": process.env.ENGINE_API_KEY } : {}),
        ...(init?.headers ?? {}),
      },
    });
  } catch {
    throw new EngineError({
      kind: "api_unreachable",
      status: 503,
      message: `The engine API is not responding at ${BACKEND_URL}.`,
    });
  }
  const text = await res.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    /* non-JSON error body */
  }
  if (!res.ok) throw new EngineError(toErrorInfo(res.status, body));
  return body as T;
}
