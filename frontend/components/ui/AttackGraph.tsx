"use client";

import "@xyflow/react/dist/style.css";
import { createContext, memo, useContext, useEffect, useMemo, useState } from "react";
import {
  Background,
  BackgroundVariant,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
  type NodeTypes,
} from "@xyflow/react";
import { Bug, Crown, Database, Flame, Globe2, Server, Siren } from "lucide-react";
import { fmtEpss } from "@/components/ui/ThreatBadges";
import type { GraphEdge, GraphNode } from "@/lib/engine";

const COL_W = 330;
const ROW_H = 124;
const HOST_W = 224;

type HostData = { node: GraphNode; depth: number };
type VulnData = { node: GraphNode; depth: number };

/** How many columns of the post-scan reveal have lit up (Infinity = all). Read by the node cards, so the node objects themselves never change. */
const RevealCtx = createContext<number>(Infinity);
/** Hosts on the route the agent just cited (explain_attack_path). Drawn with a blue ring and a blue edge. */
const RouteCtx = createContext<ReadonlySet<string>>(new Set());

const hidden = { opacity: 0, width: 1, height: 1, border: 0, minWidth: 0, minHeight: 0 } as const;

const HostNode = memo(function HostNode({ data }: NodeProps<Node<HostData>>) {
  const stage = useContext(RevealCtx);
  const onAgentRoute = useContext(RouteCtx).has(data.node.id);
  // Before the reveal reaches this column the card looks like it did before the scan.
  const n = data.depth <= stage ? data.node : { ...data.node, choke: false, kev: false, paths: 0 };
  const isNet = n.kind === "internet";
  const isStore = n.kind === "datastore";
  const tone = n.crown
    ? "border-danger/60 bg-danger/10 shadow-[0_8px_30px_-10px_rgba(232,57,26,0.55)]"
    : n.choke
      ? "border-danger/70 bg-danger/10 shadow-[0_8px_30px_-8px_rgba(232,57,26,0.6)]"
      : isNet
        ? "border-warn/50 bg-warn/10"
        : isStore
          ? "border-black/20 bg-black/[0.04]"
          : n.kev && n.paths > 0
            ? "border-danger/50 bg-danger/10 shadow-[0_6px_22px_-10px_rgba(232,57,26,0.5)]"
            : n.paths > 0
              ? "border-black/25 bg-white"
              : "border-line bg-white";
  const Icon = n.crown ? Crown : isNet ? Globe2 : isStore ? Database : n.choke ? Siren : Server;
  const iconTone = n.crown || n.choke ? "text-danger" : isNet ? "text-warn" : isStore ? "text-muted" : "text-fg";

  return (
    <div
      className={`br-node relative rounded-xl border px-3.5 py-2.5 backdrop-blur transition-[background-color,border-color,box-shadow] duration-700 ${tone} ${onAgentRoute ? "ring-2 ring-blue-600/80 ring-offset-2 ring-offset-white" : ""}`}
      style={{ width: HOST_W, ["--d" as string]: data.depth }}
    >
      {n.choke && (
        <span className="absolute -inset-1 animate-ping rounded-2xl border border-danger/40 [animation-duration:2.4s]" />
      )}
      <Handle type="target" position={Position.Left} style={hidden} isConnectable={false} />
      <Handle type="source" position={Position.Right} style={hidden} isConnectable={false} />
      {n.kev && (
        <span
          title={n.paths > 0 ? "Unpatched CISA-KEV vulnerability on a live attack path" : "Unpatched CISA-KEV vulnerability, but not on any attack path"}
          className={`absolute -right-2 -top-2 grid h-5 w-5 place-items-center rounded-full border bg-bg ${
            n.paths > 0 ? "kev-glow border-danger/70" : "border-warn/60"
          }`}
        >
          <Flame className={`h-3 w-3 ${n.paths > 0 ? "text-danger" : "text-warn"}`} aria-hidden />
        </span>
      )}
      <div className="relative flex items-center gap-2">
        <Icon className={`h-5 w-5 shrink-0 ${iconTone}`} />
        <div className="min-w-0">
          <div className="truncate font-mono text-base font-medium text-fg">{n.id}</div>
          <div className="font-mono text-xs uppercase tracking-wider text-muted">
            {n.crown ? "crown jewel" : n.choke ? "choke point" : isNet ? "entry" : isStore ? "datastore" : "host"}
            {n.paths > 0 && !isNet ? ` · ${n.paths} ${n.paths === 1 ? "path" : "paths"}` : ""}
          </div>
          {n.software && <div className="truncate font-mono text-xs text-muted" title={`${n.role ?? ""} · ${n.software}`}>{n.software}</div>}
        </div>
      </div>
    </div>
  );
});

const VulnNode = memo(function VulnNode({ data }: NodeProps<Node<VulnData>>) {
  const stage = useContext(RevealCtx);
  const hiddenYet = data.depth > stage;
  const n = data.node;
  const live = n.exploitable && !n.patched && n.paths > 0;
  const kev = !!n.kev && !n.patched;
  const tone = n.patched
    ? "border-ok/40 bg-ok/10 text-ok line-through"
    : kev && live
      ? "kev-glow border-danger/70 bg-danger/20 font-semibold text-danger"
      : kev
        ? "border-warn/50 bg-warn/10 font-medium text-warn"
        : live
        ? "border-danger/50 bg-danger/10 text-danger"
        : n.exploitable
          ? "border-warn/30 bg-warn/5 text-warn/80"
          : "border-line bg-bg text-muted";
  return (
    <div
      className={`flex items-center gap-1.5 rounded-md border px-2 py-0.5 font-mono text-[13px] transition-[opacity,transform] duration-700 ease-out ${hiddenYet ? "pointer-events-none translate-y-1 scale-95 opacity-0" : ""} ${tone}`}
      title={`${n.cve} · CVSS ${n.cvss} · EPSS ${fmtEpss(n.epss ?? 0)}${n.kev ? " · CISA KEV" : ""} · ${
        n.patched ? "patched" : live ? `${n.paths} attack paths` : "no attack path"
      }`}
    >
      {kev ? <Flame className="h-3 w-3" /> : <Bug className="h-3 w-3" />}
      {n.id} · {n.cvss}
    </div>
  );
});

const nodeTypes: NodeTypes = { host: HostNode, vuln: VulnNode };

/** Layered left-to-right layout: column = longest hop distance from the internet. */
function layout(nodes: GraphNode[], edges: GraphEdge[]): { nodes: Node[]; depth: Map<string, number> } {
  const base = nodes.filter((n) => n.kind !== "vulnerability");
  const reach = edges.filter((e) => e.type === "CAN_REACH");
  const hasIncoming = new Set(reach.map((e) => e.target));
  const depth = new Map<string, number>();
  base.forEach((n) => {
    if (n.kind === "internet") depth.set(n.id, 0);
    else if (!hasIncoming.has(n.id)) depth.set(n.id, 1); // unreachable sources sit beside the entry hosts
  });
  for (let i = 0; i < base.length; i++) {
    for (const e of reach) {
      const d = depth.get(e.source);
      if (d !== undefined && d + 1 > (depth.get(e.target) ?? -1)) depth.set(e.target, d + 1);
    }
  }

  const layers = new Map<number, GraphNode[]>();
  base.forEach((n) => {
    const d = depth.get(n.id) ?? 1;
    layers.set(d, [...(layers.get(d) ?? []), n]);
  });

  const row = new Map<string, number>();
  const preds = new Map<string, string[]>();
  reach.forEach((e) => preds.set(e.target, [...(preds.get(e.target) ?? []), e.source]));
  [...layers.keys()].sort((a, b) => a - b).forEach((d) => {
    const layer = layers.get(d)!;
    const key = (n: GraphNode) => {
      const p = (preds.get(n.id) ?? []).map((x) => row.get(x)).filter((x): x is number => x !== undefined);
      return p.length ? p.reduce((a, b) => a + b, 0) / p.length : 1e6; // sources with no known predecessor sink to the bottom
    };
    layer.sort((a, b) => key(a) - key(b) || a.id.localeCompare(b.id));
    layer.forEach((n, i) => row.set(n.id, i));
  });

  const maxRows = Math.max(...[...layers.values()].map((l) => l.length));
  const out: Node[] = base.map((n) => {
    const layer = layers.get(depth.get(n.id) ?? 1)!;
    const offset = ((maxRows - layer.length) * ROW_H) / 2;
    return {
      id: n.id,
      type: "host",
      position: { x: (depth.get(n.id) ?? 1) * COL_W, y: offset + (row.get(n.id) ?? 0) * ROW_H },
      data: { node: n, depth: depth.get(n.id) ?? 1 },
      draggable: false,
      selectable: false,
    };
  });

  const byHost = new Map<string, GraphNode[]>();
  nodes.filter((n) => n.kind === "vulnerability").forEach((v) => byHost.set(v.host!, [...(byHost.get(v.host!) ?? []), v]));
  byHost.forEach((vulns, host) => {
    const h = out.find((o) => o.id === host);
    if (!h) return;
    const hostNode = (h.data as HostData).node;
    const below = hostNode.choke || hostNode.crown ? 100 : 80; // taller cards (extra line) need the chips a bit lower
    vulns.forEach((v, i) =>
      out.push({
        id: v.id,
        type: "vuln",
        position: { x: h.position.x + (i % 2) * 96, y: h.position.y + below + Math.floor(i / 2) * 32 },
        data: { node: v, depth: depth.get(host) ?? 1 },
        draggable: false,
        selectable: false,
      })
    );
  });
  return { nodes: out, depth };
}

function toEdges(edges: GraphEdge[], depth: Map<string, number>, underlay = false, agent: ReadonlySet<string> = new Set(), cut: ReadonlySet<string> = new Set()): Edge[] {
  const out: Edge[] = [];
  for (const e of edges.filter((x) => x.type === "CAN_REACH")) {
    const id = `${e.source}>${e.target}`;
    if (underlay && e.hot) {
      // grey copy of an attack path that sits below the red one until the red flow has been wiped over it
      out.push({
        id: `${id}~base`,
        source: e.source,
        target: e.target,
        style: { stroke: "#c9c4b8", strokeWidth: 1.3 },
        markerEnd: { type: MarkerType.ArrowClosed, color: "#b3ad9f", width: 16, height: 16 },
        zIndex: 0,
      });
    }
    if (cut.has(id)) {
      out.push({
        id,
        source: e.source,
        target: e.target,
        animated: false,
        style: { stroke: "#d97706", strokeWidth: 4.5, strokeDasharray: "7 5", filter: "drop-shadow(0 0 5px rgba(217,119,6,0.55))" },
        markerEnd: { type: MarkerType.ArrowClosed, color: "#d97706", width: 18, height: 18 },
        label: "cut",
        labelStyle: { fill: "#b45309", fontWeight: 700, fontSize: 12 },
        zIndex: 22,
      });
      continue;
    }
    if (agent.has(id)) {
      out.push({
        id,
        source: e.source,
        target: e.target,
        animated: true,
        style: { stroke: "#1d4ed8", strokeWidth: 4.2, filter: "drop-shadow(0 0 6px rgba(29,78,216,0.5))" },
        markerEnd: { type: MarkerType.ArrowClosed, color: "#1d4ed8", width: 18, height: 18 },
        zIndex: 20,
      });
      continue;
    }
    out.push({
      id,
      source: e.source,
      target: e.target,
      animated: e.hot,
      className: e.hot ? "br-edge-hot" : undefined,
      style: e.hot
        ? { stroke: "#ff4b2b", strokeWidth: 2.6, filter: "drop-shadow(0 0 4px rgba(255,75,43,0.45))", ["--d" as string]: depth.get(e.source) ?? 0 }
        : { stroke: "#c9c4b8", strokeWidth: 1.3 },
      markerEnd: { type: MarkerType.ArrowClosed, color: e.hot ? "#ff4b2b" : "#b3ad9f", width: 16, height: 16 },
      zIndex: e.hot ? 10 : 0,
    });
  }
  return out;
}

/** Time between columns during the post-scan reveal; hosts light up this far into a step. */
const REVEAL_STEP_MS = 900;
const NODE_LAG = 0.85;

/**
 * `revealKey` changes (0 = never) each time a scan finishes. The graph remounts and plays one timeline: every attack
 * path is present from the first frame as a grey arrow, and its red dashed flow is wiped over it (pure CSS, delayed by
 * the column of its source), so no arrow is ever re-rendered or restarted. Hosts and findings light up a moment after
 * the arrow reaches them. When the timeline ends the grey underlays go away and it is the normal live graph.
 */
export default function AttackGraph({ nodes, edges, revealKey = 0, agentRoutes = null, cutEdges = null }: { nodes: GraphNode[]; edges: GraphEdge[]; revealKey?: number; agentRoutes?: string[][] | null; cutEdges?: [string, string][] | null }) {
  const laid = useMemo(() => layout(nodes, edges), [nodes, edges]);
  const maxDepth = useMemo(() => Math.max(1, ...laid.depth.values()), [laid.depth]);

  const [rv, setRv] = useState({ key: 0, nodeStage: Infinity, done: true });
  const live = revealKey !== 0 && rv.key === revealKey;
  const revealing = revealKey !== 0 && !(live && rv.done);
  const nodeStage = revealKey === 0 ? Infinity : live ? rv.nodeStage : 0;
  useEffect(() => {
    if (!revealKey) return;
    const timers: number[] = [];
    const at = (ms: number, patch: { nodeStage?: number; done?: boolean }) =>
      timers.push(window.setTimeout(() => setRv((r) => ({ key: revealKey, nodeStage: r.key === revealKey ? r.nodeStage : 0, done: false, ...patch })), ms));
    for (let st = 1; st <= maxDepth; st++) at((st - 1 + NODE_LAG) * REVEAL_STEP_MS, { nodeStage: st });
    at((maxDepth + 0.7) * REVEAL_STEP_MS, { nodeStage: Infinity, done: true });
    return () => timers.forEach(window.clearTimeout);
  }, [revealKey, maxDepth]);

  const rfNodes = laid.nodes; // stable objects: replacing them would make React Flow re-measure and briefly drop their arrows
  const routeEdges = useMemo(() => new Set((agentRoutes ?? []).flatMap((r) => r.slice(0, -1).map((a, i) => `${a}>${r[i + 1]}`))), [agentRoutes]);
  const routeNodes = useMemo(() => new Set((agentRoutes ?? []).flat()), [agentRoutes]);
  const cutSet = useMemo(() => new Set((cutEdges ?? []).map(([a, b]) => `${a}>${b}`)), [cutEdges]);
  const rfEdges = useMemo(() => toEdges(edges, laid.depth, revealing, routeEdges, cutSet), [edges, laid.depth, revealing, routeEdges, cutSet]);

  return (
    <RevealCtx.Provider value={nodeStage}>
    <RouteCtx.Provider value={routeNodes}>
    <div key={revealKey} className={`relative h-full w-full ${revealing ? "br-revealing" : ""}`}>
      <ReactFlow
        nodes={rfNodes}
        edges={rfEdges}
        nodeTypes={nodeTypes}
        colorMode="light"
        fitView
        fitViewOptions={{ padding: 0.06 }}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
        zoomOnScroll={false}
        preventScrolling={false}
        minZoom={0.4}
        maxZoom={1.6}
        proOptions={{ hideAttribution: false }}
      >
        <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="rgba(13,13,15,0.12)" />
      </ReactFlow>
      <div className="pointer-events-none absolute bottom-2 left-3 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[11px] text-muted">
        <Legend color="bg-fg" label="host" />
        <Legend color="bg-danger" label="vulnerability on a path" />
        <Legend color="kev-glow bg-danger" label="CISA KEV on a path" />
        <Legend color="bg-warn" label="CISA KEV, not reachable" />
        <Legend color="bg-danger ring-2 ring-danger/40" label="choke point" />
        <Legend color="bg-warn" label="entry" />
        <span className="flex items-center gap-1.5">
          <span className="h-0.5 w-4 bg-danger" /> attack path
        </span>
      </div>
    </div>
    </RouteCtx.Provider>
    </RevealCtx.Provider>
  );
}

function Legend({ color, label }: { color: string; label: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className={`h-2 w-2 rounded-full ${color}`} /> {label}
    </span>
  );
}
