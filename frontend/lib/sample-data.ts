/**
 * Static copy of the sample workspace, used ONLY by the marketing page (the dashboard reads the live FalkorDB engine).
 * Keep in sync with backend/seed.py. CVE ids are real; CVSS/KEV/EPSS values are an illustrative snapshot.
 */

export type NodeKind = "internet" | "host" | "datastore";

export interface GraphNode {
  id: string;
  kind: NodeKind;
  crown?: boolean;
  x: number; // layout column (0-3)
  y: number; // layout row
}

export interface Finding {
  id: string;
  host: string;
  cve: string;
  cvss: number;
  epss: number;
  kev: boolean;
}

export type Tier = "auto" | "approval" | "monitor";

export const NODES: GraphNode[] = [
  { id: "internet", kind: "internet", x: 0, y: 2 },
  { id: "edge-nginx", kind: "host", x: 1, y: 0 },
  { id: "edge-apache", kind: "host", x: 1, y: 1 },
  { id: "edge-node", kind: "host", x: 1, y: 2 },
  { id: "legacy-ftp", kind: "host", x: 1, y: 4 },
  { id: "api-gateway", kind: "host", x: 2, y: 1 },
  { id: "worker-java", kind: "host", x: 2, y: 2.4 },
  { id: "batch-legacy", kind: "host", x: 2, y: 3.6 },
  { id: "db-customers", kind: "datastore", crown: true, x: 3, y: 1.6 },
  { id: "cache-redis", kind: "host", x: 3, y: 3 },
  { id: "archive-ftp", kind: "datastore", x: 3, y: 4.2 },
];

export const EDGES: [string, string][] = [
  ["internet", "edge-nginx"], ["internet", "edge-apache"], ["internet", "edge-node"], ["internet", "legacy-ftp"],
  ["edge-nginx", "api-gateway"], ["edge-apache", "api-gateway"], ["edge-node", "api-gateway"], ["edge-apache", "worker-java"],
  ["api-gateway", "db-customers"], ["worker-java", "db-customers"], ["worker-java", "cache-redis"],
  ["legacy-ftp", "archive-ftp"], ["batch-legacy", "db-customers"],
];

export const FINDINGS: Finding[] = [
  { id: "F1", host: "edge-nginx", cve: "CVE-2021-23017", cvss: 8.1, epss: 0.12, kev: false },
  { id: "F2", host: "edge-apache", cve: "CVE-2021-41773", cvss: 7.5, epss: 0.97, kev: true },
  { id: "F3", host: "edge-node", cve: "CVE-2022-24999", cvss: 7.5, epss: 0.15, kev: false },
  { id: "F4", host: "api-gateway", cve: "CVE-2014-0160", cvss: 7.5, epss: 0.97, kev: true },
  { id: "F5", host: "worker-java", cve: "CVE-2021-44832", cvss: 6.6, epss: 0.2, kev: false },
  { id: "F6", host: "legacy-ftp", cve: "CVE-2021-44228", cvss: 10.0, epss: 0.97, kev: true },
  { id: "F7", host: "batch-legacy", cve: "CVE-2014-6271", cvss: 9.8, epss: 0.97, kev: true },
  { id: "F8", host: "edge-node", cve: "CVE-2019-10744", cvss: 9.1, epss: 0.01, kev: false },
  { id: "F9", host: "cache-redis", cve: "CVE-2022-35977", cvss: 5.5, epss: 0.02, kev: false },
];

const isExploitable = (f: Finding) => f.kev || f.epss >= 0.1;

/** Hosts that currently have at least one unpatched exploitable finding. */
function exploitableHosts(patched: string[]): Set<string> {
  return new Set(FINDINGS.filter((f) => isExploitable(f) && !patched.includes(f.id)).map((f) => f.host));
}

/** Internet → crown-jewel paths through exploitable hosts (mirrors the Cypher in the engine). */
export function attackPaths(patched: string[] = [], maxDepth = 6): string[][] {
  const hot = exploitableHosts(patched);
  const kind = new Map(NODES.map((n) => [n.id, n]));
  const out: string[][] = [];
  const walk = (path: string[]) => {
    const here = path[path.length - 1];
    const node = kind.get(here);
    if (node?.kind === "datastore") {
      if (node.crown) out.push(path);
      return;
    }
    if (path.length > maxDepth) return;
    for (const [a, b] of EDGES) {
      if (a !== here || path.includes(b)) continue;
      const next = kind.get(b);
      if (next?.kind === "datastore" || hot.has(b)) walk([...path, b]);
    }
  };
  walk(["internet"]);
  return out;
}

const crownNeighbours = new Set(
  EDGES.filter(([, b]) => NODES.find((n) => n.id === b)?.crown).map(([a]) => a)
);

export interface RankedFinding extends Finding {
  exploitable: boolean;
  paths: number;
  tier: Tier;
  reason: string;
}

/** Rank by attack paths, then assign an autonomy tier from graph facts (never from model opinion). */
export function rankFindings(patched: string[] = []): RankedFinding[] {
  const paths = attackPaths(patched);
  const hostLoad = new Map<string, number>();
  paths.forEach((p) => p.forEach((h) => hostLoad.set(h, (hostLoad.get(h) ?? 0) + 1)));
  const maxLoad = Math.max(0, ...[...hostLoad.entries()].filter(([h]) => h !== "internet" && h !== "db-customers").map(([, c]) => c));

  return FINDINGS.map((f) => {
    const exploitable = isExploitable(f);
    const onPaths = exploitable && !patched.includes(f.id) ? hostLoad.get(f.host) ?? 0 : 0;
    let tier: Tier = "auto";
    let reason = "Leaf host on a single path — reversible patch";
    if (onPaths === 0) {
      tier = "monitor";
      reason = exploitable ? "Not reachable on any path to a crown jewel" : "Low exploit likelihood (EPSS < 0.1, not in KEV)";
    } else if (onPaths === maxLoad && maxLoad > 1) {
      tier = "approval";
      reason = `Choke point — sits on ${onPaths} of ${paths.length} paths`;
    } else if (crownNeighbours.has(f.host)) {
      tier = "approval";
      reason = "Directly adjacent to a crown jewel";
    } else if (onPaths > 1) {
      tier = "approval";
      reason = `Sits on ${onPaths} paths — wide blast radius`;
    }
    return { ...f, exploitable, paths: onPaths, tier, reason };
  }).sort((a, b) => b.paths - a.paths || b.cvss - a.cvss);
}
