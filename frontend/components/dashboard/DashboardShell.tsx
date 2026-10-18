"use client";

import dynamic from "next/dynamic";
import { useCallback, useEffect, useMemo, useState, useSyncExternalStore } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Bot, Check, Download, ChevronDown, History, Lightbulb, Loader2, Lock, RefreshCw, RotateCcw, Sparkles, Upload, UserCheck, X } from "lucide-react";
import ScanTerminal from "./ScanTerminal";
import EngineError from "./EngineError";
import AppFrame from "./AppFrame";
import PricingModal from "@/components/pricing/PricingModal";
import AdvisorPanel from "./AdvisorPanel";
import ImportModal from "./ImportModal";
import { EpssMeter, KevBadge } from "@/components/ui/ThreatBadges";
import type { Plan } from "@/lib/plans";
import { toErrorInfo, type EngineErrorInfo, type Finding, type AutoAllResult, type Scan, type Tier, type FixResult } from "@/lib/engine";

const AttackGraph = dynamic(() => import("@/components/ui/AttackGraph"), {
  ssr: false,
  loading: () => <GraphSkeleton />,
});

type User = { name: string; email: string; image: string | null; plan: Plan };
export type Initial = { scan: Scan } | { error: EngineErrorInfo };

const tierStyle: Record<Tier, string> = {
  auto: "border-ok/30 bg-ok/10 text-ok",
  approval: "border-warn/30 bg-warn/10 text-warn",
  monitor: "border-line bg-black/[0.04] text-muted",
  patched: "border-ok/30 bg-ok/10 text-ok",
};
const tierLabel: Record<Tier, string> = { auto: "AUTO", approval: "NEEDS APPROVAL", monitor: "MONITOR", patched: "PATCHED" };

/** Calls the session-protected proxy to the Python engine. */
async function engine<T>(path: string, init?: RequestInit): Promise<{ data: T } | { error: EngineErrorInfo }> {
  try {
    const res = await fetch(`/api/engine/${path}`, {
      ...init,
      headers: { "Content-Type": "application/json" },
      cache: "no-store",
    });
    const body = await res.json().catch(() => null);
    if (!res.ok) return { error: toErrorInfo(res.status, body && body.kind ? { ...body, error: body.kind } : body) };
    return { data: body as T };
  } catch {
    return { error: { kind: "api_unreachable", status: 503, message: "Could not reach the dashboard server." } };
  }
}

export default function DashboardShell({ user, initial, mock }: { user: User; initial: Initial; mock: boolean }) {
  const [scan, setScan] = useState<Scan | null>("scan" in initial ? initial.scan : null);
  const [error, setError] = useState<EngineErrorInfo | null>("error" in initial ? initial.error : null);
  const [refreshing, setRefreshing] = useState(false);
  const [busyFix, setBusyFix] = useState<string | null>(null);
  const [bulk, setBulk] = useState(false);
  const [plan, setPlan] = useState<Plan>(user.plan);
  const [pricingOpen, setPricingOpen] = useState(false);
  const [advisorOpen, setAdvisorOpen] = useState(false);
  const [confirmRestore, setConfirmRestore] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [agentRoutes, setAgentRoutes] = useState<string[][] | null>(null); // routes the advisor just cited, drawn on the graph
  // First visit shows only the topology and a "run scan" prompt; results appear after the first scan.
  const [scannedNow, setScannedNow] = useState<boolean>("scan" in initial && (initial.scan.summary.patched > 0 || initial.scan.history.length > 0));
  const scannedBefore = useSyncExternalStore(
    () => () => {},
    () => {
      try {
        return window.localStorage.getItem("br-scanned") === "1";
      } catch {
        return false;
      }
    },
    () => false
  );
  const scanned = scannedNow || scannedBefore;
  const [showAll, setShowAll] = useState(false);
  const [revealKey, setRevealKey] = useState(0); // +1 each time a scan finishes: the graph replays its path animation
  const [scanKey, setScanKey] = useState(0); // bumping it remounts the scan panel back to its idle state
  const markScanned = useCallback(() => {
    setScannedNow(true);
    setRevealKey((k) => k + 1);
    try {
      window.localStorage.setItem("br-scanned", "1");
    } catch {}
  }, []);

  // Cmd/Ctrl+K toggles the advisor
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setAdvisorOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  const [toast, setToast] = useState<{ tone: "ok" | "err"; text: string } | null>(null);

  const say = useCallback((tone: "ok" | "err", text: string) => {
    setToast({ tone, text });
    window.setTimeout(() => setToast((t) => (t?.text === text ? null : t)), 5000);
  }, []);

  const rescan = useCallback(async (): Promise<Scan | null> => {
    setRefreshing(true);
    const r = await engine<Scan>("scan");
    setRefreshing(false);
    if ("error" in r) {
      setError(r.error);
      return null;
    }
    setError(null);
    setScan(r.data);
    return r.data;
  }, []);

  const applyFix = useCallback(
    async (f: Finding): Promise<Scan | null> => {
      setBusyFix(f.id);
      const r = await engine<FixResult>(f.tier === "auto" ? "fix/auto" : "fix/approve", {
        method: "POST",
        body: JSON.stringify({ finding_id: f.id }),
      });
      setBusyFix(null);
      if ("error" in r) {
        if (r.error.kind === "engine_unavailable" || r.error.kind === "api_unreachable") setError(r.error);
        else say("err", r.error.message);
        return null;
      }
      setScan(r.data.scan);
      say("ok", `${f.cve} patched on ${f.host} · attack paths ${r.data.paths_before} → ${r.data.paths_after}`);
      return r.data.scan;
    },
    [say]
  );

  const autoFixSafe = useCallback(async () => {
    if (plan !== "pro") return setPricingOpen(true);
    setBulk(true);
    const r = await engine<AutoAllResult>("fix/auto-all", { method: "POST" });
    setBulk(false);
    if ("error" in r) {
      if (r.error.kind === "upgrade_required") {
        setPlan("free"); // the server is the source of truth: the plan changed since this page loaded
        setPricingOpen(true);
      } else if (r.error.kind === "engine_unavailable" || r.error.kind === "api_unreachable") setError(r.error);
      else say("err", r.error.message);
      return;
    }
    setScan(r.data.scan);
    say(
      "ok",
      r.data.applied.length
        ? `Auto-fixed ${r.data.applied.length} ${r.data.applied.length === 1 ? "finding" : "findings"} · attack paths ${r.data.paths_before} → ${r.data.paths_after}`
        : "Nothing safe to auto-fix right now."
    );
  }, [plan, say]);

  const resetDemo = useCallback(async () => {
    setConfirmRestore(false);
    setRefreshing(true);
    const r = await engine<Scan>("reset", { method: "POST" });
    setRefreshing(false);
    if ("error" in r) return setError(r.error);
    setError(null);
    setScan(r.data);
    // Back to the first-visit state: hide results, forget the first scan, reset the scan panel.
    setAgentRoutes(null);
    setScannedNow(false);
    setShowAll(false);
    setScanKey((k) => k + 1);
    try {
      window.localStorage.removeItem("br-scanned");
    } catch {}
    say("ok", "Demo restored for everyone · run a new scan");
  }, [say]);

  const ownWorkspace = scan?.workspace === "own";
  // The advisor's route stays on the graph only while it is still an attack path: fix a host on it and it disappears.
  const liveRoutes = useMemo(() => {
    if (!agentRoutes || !scan) return null;
    const live = new Set(scan.paths.map((p) => p.join(">")));
    const keep = agentRoutes.filter((r) => live.has(r.join(">")));
    return keep.length ? keep : null;
  }, [agentRoutes, scan]);

  const importData = useCallback(
    async (payload: unknown): Promise<string | null> => {
      const r = await engine<{ scan: Scan; imported: { findings: number; hosts: number }; live_feeds: boolean; warnings?: string[] }>("import", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      if ("error" in r) return r.error.message;
      setError(null);
      setScan(r.data.scan);
      setAgentRoutes(null);
      setScannedNow(false);
      setShowAll(false);
      setScanKey((k) => k + 1);
      try {
        window.localStorage.removeItem("br-scanned");
      } catch {}
      setImportOpen(false);
      say("ok", `Imported ${r.data.imported.hosts} hosts and ${r.data.imported.findings} findings · ${r.data.live_feeds ? "live KEV/EPSS applied" : "feeds unreachable, using CVSS fallback"}${r.data.warnings?.length ? ` · ${r.data.warnings[0]}` : ""}`);
      return null;
    },
    [say]
  );

  const downloadPlaybook = useCallback(async () => {
    const r = await engine<{ playbook_yaml: string; fixes: unknown[] }>("playbook?scope=applied");
    if ("error" in r) return say("err", r.error.message);
    const url = URL.createObjectURL(new Blob([r.data.playbook_yaml], { type: "text/yaml" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: "blastradius-remediation.yml" });
    a.click();
    URL.revokeObjectURL(url);
    say("ok", `Remediation playbook downloaded (${r.data.fixes.length} fix${r.data.fixes.length === 1 ? "" : "es"}). Review it and run with --check --diff first.`);
  }, [say]);

  const backToSample = useCallback(async () => {
    setRefreshing(true);
    await engine("workspace/sample", { method: "POST" });
    const fresh = await rescan();
    setRefreshing(false);
    if (fresh) {
      setAgentRoutes(null);
      setScannedNow(false);
      setShowAll(false);
      setScanKey((k) => k + 1);
      try {
        window.localStorage.removeItem("br-scanned");
      } catch {}
      say("ok", "Back on the shared sample data");
    }
  }, [rescan, say]);

  const actionable = scan?.findings.filter((f) => f.tier === "auto" || f.tier === "approval") ?? [];
  const autoCount = actionable.filter((f) => f.tier === "auto").length;
  const s = scan?.summary;
  const dash = "—";
  const stats = s
    ? [
        {
          label: "Attack paths",
          value: scanned ? s.paths : dash,
          tone: !scanned ? "text-muted" : s.paths ? "text-danger" : "text-ok",
          sub: scanned ? `${s.exploitable} exploitable · ${s.kev} in CISA KEV` : "run a scan to find out",
          subTone: scanned && s.kev ? "text-danger" : "text-muted",
        },
        { label: "Auto-fixable", value: scanned ? s.auto : dash, tone: scanned ? "text-ok" : "text-muted" },
        { label: "Need approval", value: scanned ? s.approval : dash, tone: scanned ? "text-warn" : "text-muted" },
        ...(s.patched > 0 ? [{ label: "Patched", value: s.patched, tone: "text-accent" }] : []),
      ]
    : [];

  // Before the first scan the graph shows only the network: no hot paths, no findings.
  const graphView = useMemo(() => {
    if (!scan) return null;
    if (scanned) return { nodes: scan.nodes, edges: scan.edges };
    return {
      nodes: scan.nodes.filter((n) => n.kind !== "vulnerability").map((n) => ({ ...n, choke: false, kev: false, paths: 0 })),
      edges: scan.edges.filter((e) => e.type === "CAN_REACH").map((e) => ({ ...e, hot: false })),
    };
  }, [scan, scanned]);
  const firstName = user.name.split(" ")[0] || "there";
  const visible = showAll ? actionable : actionable.slice(0, 3);
  // Advisor starter questions use the live graph, so they never ask about something already patched.
  const topFix = actionable.find((f) => f.paths > 0) ?? actionable[0];
  const advisorSuggestions = [
    actionable.length ? "Which vulnerability should I patch first?" : "Which findings should I still keep an eye on?",
    "Which findings are in CISA KEV?",
    topFix ? `What if I patch ${topFix.id}?` : "Why are there no attack paths left?",
    "Draft a ticket for the top finding",
    autoCount > 0 ? "Fix everything that is safe, and escalate the rest" : "What did you do earlier?",
  ];

  const status = (
    <span className="hidden items-center gap-1.5 whitespace-nowrap font-mono text-xs text-muted md:flex">
      <span className={`h-1.5 w-1.5 rounded-full ${error ? "bg-danger" : "bg-ok"}`} />
      {error ? "engine offline" : "engine live · FalkorDB"}
    </span>
  );
  const advisorButton = (
    <button
      onClick={() => setAdvisorOpen((o) => !o)}
      aria-pressed={advisorOpen}
      title="Ask the advisor (Ctrl/Cmd+K)"
      className={`flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-md border px-2.5 py-1 font-mono text-xs transition ${
        advisorOpen ? "border-accent/60 bg-accent/20 text-accent" : "border-accent/30 bg-accent/10 text-accent hover:bg-accent/20"
      }`}
    >
      <Bot className="h-3.5 w-3.5" />
      <span className="hidden sm:inline">Ask advisor</span>
      <kbd className="hidden rounded border border-accent/30 px-1 text-[9px] text-accent/80 md:inline">⌘K</kbd>
    </button>
  );

  return (
    <AppFrame
      user={{ ...user, plan }}
      active="dashboard"
      headerStatus={
        <>
          {status}
          {advisorButton}
        </>
      }
      workspace={ownWorkspace ? "your data" : "sample"}
      sidebarFooter={
        <div className="space-y-1">
          <button
            onClick={() => setImportOpen(true)}
            className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-sm leading-tight text-accent transition hover:bg-accent/10"
          >
            <Upload className="h-4 w-4" />
            Use your own data
          </button>
          <button
            onClick={ownWorkspace ? backToSample : () => setConfirmRestore(true)}
            disabled={refreshing}
            className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-sm leading-tight text-muted transition hover:bg-black/[0.04] hover:text-fg disabled:opacity-50"
          >
            <RotateCcw className="h-4 w-4" />
            {ownWorkspace ? "Back to sample data" : "Restore demo for everyone"}
          </button>
        </div>
      }
    >
      <div className="relative flex flex-col gap-4 p-4 sm:p-6">
          <AnimatePresence>
            {toast && (
              <motion.div
                initial={{ opacity: 0, y: -12 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -12 }}
                role="status"
                className={`fixed right-4 top-20 z-50 flex max-w-sm items-start gap-2 rounded-xl border px-4 py-3 text-sm shadow-xl backdrop-blur ${
                  toast.tone === "ok" ? "border-ok/30 bg-ok/10 text-ok" : "border-danger/30 bg-danger/10 text-danger"
                }`}
              >
                {toast.tone === "ok" ? <Check className="mt-0.5 h-4 w-4 shrink-0" /> : <X className="mt-0.5 h-4 w-4 shrink-0" />}
                {toast.text}
              </motion.div>
            )}
          </AnimatePresence>

          {error && !scan ? (
            <EngineError error={error} onRetry={rescan} retrying={refreshing} />
          ) : scan ? (
            <>
              {error && (
                <div className="flex items-center justify-between rounded-xl border border-danger/30 bg-danger/10 px-4 py-2 text-sm text-danger">
                  <span>{error.message} Showing the last known state.</span>
                  <button onClick={rescan} className="flex items-center gap-1 underline">
                    {refreshing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />} retry
                  </button>
                </div>
              )}

              <div className="order-first flex flex-wrap items-end justify-between gap-3 pb-1">
                <div>
                  <p className="font-mono text-[11px] uppercase tracking-widest text-muted">
                    {firstName} · {ownWorkspace ? "your workspace" : "sample workspace"}
                  </p>
                  <h1 className="mt-1 text-3xl leading-tight tracking-tight sm:text-4xl">
                    {!scanned ? (
                      <>
                        Find what&apos;s <em className="font-serif italic text-accent">reachable</em>.
                      </>
                    ) : scan.summary.paths ? (
                      <>
                        {scan.summary.paths} attack {scan.summary.paths === 1 ? "path reaches" : "paths reach"}{" "}
                        <em className="font-serif italic text-danger">your crown jewel</em>.
                      </>
                    ) : (
                      <>
                        No attack paths. <em className="font-serif italic text-ok">All clear.</em>
                      </>
                    )}
                  </h1>
                </div>
              </div>

              <div id="overview" className={`grid scroll-mt-20 gap-3 ${stats.length === 4 ? "grid-cols-2 lg:grid-cols-4" : "grid-cols-1 sm:grid-cols-3"}`}>
                {stats.map((st, i) => (
                  <motion.div
                    key={st.label}
                    initial={{ opacity: 0, y: 12 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.05 + i * 0.05 }}
                    className="panel-sheen rounded-3xl border border-line bg-panel p-5"
                  >
                    <div className="text-xs text-muted">{st.label}</div>
                    <AnimatePresence mode="popLayout" initial={false}>
                      <motion.div
                        key={String(st.value)}
                        initial={{ opacity: 0, y: 10, scale: 0.9 }}
                        animate={{ opacity: 1, y: 0, scale: 1 }}
                        exit={{ opacity: 0, y: -10 }}
                        transition={{ duration: 0.25 }}
                        className={`mt-1 font-mono text-3xl font-semibold ${st.tone}`}
                      >
                        {st.value}
                      </motion.div>
                    </AnimatePresence>
                    {"sub" in st && st.sub && <div className={`mt-0.5 font-mono text-[10px] ${st.subTone}`}>{st.sub}</div>}
                  </motion.div>
                ))}
              </div>

              <div id="graph" className="panel-sheen relative scroll-mt-20 rounded-3xl border border-line bg-panel p-4">
                <div className="flex items-center justify-between">
                  <p className="font-mono text-xs text-muted">
                    {scanned ? "attack graph · live from FalkorDB" : "your network · run a scan to reveal attack paths"}
                  </p>
                  {liveRoutes && (
                    <button onClick={() => setAgentRoutes(null)} className="rounded-full border border-blue-600/40 bg-blue-600/10 px-2.5 py-0.5 font-mono text-[11px] text-blue-700 hover:bg-blue-600/20">
                      advisor route · {liveRoutes.length} shown · clear ×
                    </button>
                  )}
                  {scanned && (
                    <p className={`font-mono text-xs ${scan.summary.paths ? "text-danger" : "text-ok"}`}>
                      {scan.summary.paths} live {scan.summary.paths === 1 ? "path" : "paths"}
                    </p>
                  )}
                </div>
                <div className="mt-2 h-[700px] overflow-hidden rounded-2xl border border-line bg-bg">
                  {graphView && <AttackGraph nodes={graphView.nodes} edges={graphView.edges} revealKey={revealKey} agentRoutes={liveRoutes} />}
                </div>
                {(refreshing || busyFix) && (
                  <div className="pointer-events-none absolute inset-0 grid place-items-center rounded-2xl bg-bg/40 backdrop-blur-[1px]">
                    <Loader2 className="h-6 w-6 animate-spin text-accent" />
                  </div>
                )}
              </div>

              {/* Before the first scan the call to action sits right under the heading; afterwards it drops below the graph. */}
              <div className={scanned ? "" : "order-first"}>
                <ScanTerminal key={scanKey} onRescan={rescan} onFinished={markScanned} liveScan={scanned ? scan : null} label={ownWorkspace ? "your workspace" : "sample workspace"} />
              </div>

              {scanned && (
                <div id="fix" className="panel-sheen scroll-mt-20 rounded-3xl border border-line bg-panel">
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-3">
                    <p className="flex items-center gap-2 text-sm font-medium">
                      <Lightbulb className="h-4 w-4 text-accent" /> Fix first
                      <span className="font-mono text-xs font-normal text-muted">ranked by attack paths</span>
                    </p>
                    {autoCount > 0 && (
                      <button
                        onClick={autoFixSafe}
                        disabled={bulk || !!busyFix}
                        title={plan === "pro" ? undefined : "Pro feature: click to see plans"}
                        className={`flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs transition disabled:opacity-40 ${
                          plan === "pro"
                            ? "border-ok/30 bg-ok/10 text-ok hover:bg-ok/20"
                            : "border-accent/30 bg-accent/10 text-accent hover:bg-accent/20"
                        }`}
                      >
                        {bulk ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : plan === "pro" ? (
                          <Sparkles className="h-3.5 w-3.5" />
                        ) : (
                          <Lock className="h-3.5 w-3.5" />
                        )}
                        Auto-fix all safe{plan === "pro" ? ` (${autoCount})` : ""}
                        {plan !== "pro" && (
                          <span className="rounded border border-accent/40 px-1 font-mono text-[9px] uppercase">Pro</span>
                        )}
                      </button>
                    )}
                  </div>
                  {actionable.length === 0 ? (
                    <p className="px-4 py-8 text-center text-sm text-muted">
                      {scan.summary.paths === 0 ? "No attack paths remain. Nothing to fix." : "No actionable findings."}
                    </p>
                  ) : (
                    <ul className="divide-y divide-line">
                      <AnimatePresence initial={false}>
                        {visible.map((f, idx) => (
                          <motion.li
                            key={f.id}
                            layout
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0, height: 0 }}
                            className="flex flex-col gap-3 overflow-hidden px-5 py-4 sm:flex-row sm:items-center sm:gap-5"
                          >
                            <span className="hidden w-8 shrink-0 font-serif text-3xl italic leading-none text-muted/60 sm:block">{String(idx + 1).padStart(2, "0")}</span>
                            <div className="min-w-0 flex-1">
                              <div className="flex flex-wrap items-center gap-2 font-mono text-sm">
                                <span>{f.cve}</span>
                                <span className="text-muted">· {f.host}</span>
                                <span className="text-muted">· CVSS {f.cvss}</span>
                                {f.kev && <KevBadge />}
                              </div>
                              <p className="mt-0.5 text-xs text-muted">{f.reason}</p>
                              {(f.product || f.summary) && (
                                <p className="mt-0.5 line-clamp-1 text-xs text-muted/70" title={f.summary ?? undefined}>
                                  {f.product}
                                  {f.summary ? ` · ${f.summary}` : ""}
                                </p>
                              )}
                            </div>
                            <div className="flex flex-wrap items-center gap-3">
                              <EpssMeter epss={f.epss} />
                              <span className="font-mono text-xs text-danger">{f.paths} {f.paths === 1 ? "path" : "paths"}</span>
                              <span className={`rounded-md border px-2 py-0.5 font-mono text-[10px] ${tierStyle[f.tier]}`}>
                                {tierLabel[f.tier]}
                              </span>
                              <button
                                onClick={() => applyFix(f)}
                                disabled={!!busyFix || bulk}
                                className={`flex min-w-[112px] items-center justify-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium transition disabled:opacity-50 ${
                                  f.tier === "auto"
                                    ? "border-ok/40 bg-ok/10 text-ok hover:bg-ok/20"
                                    : "border-warn/40 bg-warn/10 text-warn hover:bg-warn/20"
                                }`}
                              >
                                {busyFix === f.id ? (
                                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                                ) : f.tier === "auto" ? (
                                  <Check className="h-3.5 w-3.5" />
                                ) : (
                                  <UserCheck className="h-3.5 w-3.5" />
                                )}
                                {f.tier === "auto" ? "Apply fix" : "Approve fix"}
                              </button>
                            </div>
                          </motion.li>
                        ))}
                      </AnimatePresence>
                    </ul>
                  )}
                  {actionable.length > 3 && (
                    <button
                      onClick={() => setShowAll((v) => !v)}
                      className="flex w-full items-center justify-center gap-1.5 border-t border-line px-4 py-2.5 font-mono text-xs text-muted transition hover:text-fg"
                    >
                      <ChevronDown className={`h-3.5 w-3.5 transition ${showAll ? "rotate-180" : ""}`} />
                      {showAll ? "show fewer" : `show all ${actionable.length} findings`}
                    </button>
                  )}
                </div>
              )}

              {scan.history.length > 0 && (
                <details id="applied" className="group scroll-mt-20 rounded-2xl border border-line bg-panel">
                  <summary className="flex cursor-pointer list-none items-center gap-2 px-4 py-3 text-sm font-medium">
                    <History className="h-4 w-4 text-accent" /> Applied fixes
                    <span className="font-mono text-xs font-normal text-muted">{scan.history.length} · each with a rollback note</span>
                    <ChevronDown className="ml-auto h-4 w-4 text-muted transition group-open:rotate-180" />
                  </summary>
                  <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line px-4 py-2">
                    <p className="text-xs text-muted">Export what was decided as an Ansible playbook with rollback. BlastRadius changes no server itself.</p>
                    <button onClick={downloadPlaybook} className="flex items-center gap-1.5 rounded-md border border-accent/30 bg-accent/10 px-3 py-1.5 text-xs text-accent transition hover:bg-accent/20">
                      <Download className="h-3.5 w-3.5" /> Download remediation playbook
                    </button>
                  </div>
                  <ul className="divide-y divide-line border-t border-line">
                    {scan.history.map((h) => (
                      <li key={h.id} className="px-4 py-3 text-sm">
                        <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
                          <span className="text-fg">{h.id}</span>
                          <span className="text-muted">
                            · {h.cve} · {h.host}
                          </span>
                          <span className={`rounded border px-1.5 text-[10px] ${h.mode === "auto" ? tierStyle.auto : tierStyle.approval}`}>
                            {h.mode === "auto" ? "AUTO-APPLIED" : "HUMAN-APPROVED"}
                          </span>
                        </div>
                        <p className="mt-1 text-xs text-muted">Rollback: {h.rollback}</p>
                      </li>
                    ))}
                  </ul>
                </details>
              )}

              <p className="px-1 font-mono text-[10px] text-muted/70">{scan.data_notice}</p>
            </>
          ) : null}
        </div>
      <AnimatePresence>{importOpen && <ImportModal onClose={() => setImportOpen(false)} onImport={importData} />}</AnimatePresence>
      <AnimatePresence>
        {confirmRestore && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-[60] grid place-items-center bg-black/40 p-4"
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="restore-title"
            onClick={() => setConfirmRestore(false)}
            onKeyDown={(e) => e.key === "Escape" && setConfirmRestore(false)}
          >
            <div className="w-full max-w-sm rounded-2xl border border-line bg-bg p-6 shadow-2xl" onClick={(e) => e.stopPropagation()}>
              <h2 id="restore-title" className="text-lg font-medium">Restore the demo for everyone?</h2>
              <p className="mt-2 text-sm text-muted">
                The sample workspace is shared by every visitor. This undoes every applied fix and puts all attack paths back.
              </p>
              <div className="mt-5 flex justify-end gap-2">
                <button autoFocus onClick={() => setConfirmRestore(false)} className="h-10 rounded-full border border-line px-4 text-sm text-muted transition hover:text-fg">
                  Cancel
                </button>
                <button onClick={resetDemo} className="btn-chrome h-10 rounded-full px-5 text-sm font-semibold">
                  Restore demo
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
      <AdvisorPanel open={advisorOpen} onClose={() => setAdvisorOpen(false)} suggestions={advisorSuggestions} onAgentAction={() => void rescan()} onRoutes={(r) => setAgentRoutes(r)} />
      <PricingModal open={pricingOpen} onClose={() => setPricingOpen(false)} mock={mock} />
    </AppFrame>
  );
}

export function GraphSkeleton() {
  return (
    <div className="grid h-full w-full animate-pulse place-items-center bg-panel-2/40 font-mono text-xs text-muted">
      <Loader2 className="h-5 w-5 animate-spin text-accent" />
    </div>
  );
}
