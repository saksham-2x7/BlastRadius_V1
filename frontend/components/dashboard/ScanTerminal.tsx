"use client";

import { useEffect, useRef, useState } from "react";
import { Loader2, Play, RotateCcw } from "lucide-react";
import type { Scan } from "@/lib/engine";

type Line = { text: string; tone: "cmd" | "info" | "hit" | "ok" | "warn" | "muted" };

function buildScript(scan: Scan): Line[] {
  const reach = scan.edges.filter((e) => e.type === "CAN_REACH").length;
  const lines: Line[] = [
    { text: "$ blastradius scan --workspace sample", tone: "cmd" },
    {
      text: `[graph]  ${scan.nodes.filter((n) => n.kind !== "vulnerability").length} nodes · ${reach} CAN_REACH edges · ${scan.findings.length} findings`,
      tone: "info",
    },
    { text: "[cypher] MATCH p=(:Internet)-[:CAN_REACH*1..6]->(:DataStore {crown:true})", tone: "muted" },
    { text: `[paths]  ${scan.paths.length} attack paths to the crown jewel`, tone: scan.paths.length ? "hit" : "ok" },
    ...scan.paths.map((p) => ({ text: `         ${p.join(" → ")}`, tone: "muted" as const })),
  ];
  scan.findings
    .filter((f) => f.paths > 0)
    .forEach((f) => lines.push({ text: `[rank]   ${f.cve} CVSS ${f.cvss} EPSS ${Math.round(f.epss * 100)}%${f.kev ? " KEV" : ""} → ${f.paths} ${f.paths === 1 ? "path" : "paths"}`, tone: "hit" }));
  scan.findings
    .filter((f) => f.cvss >= 9 && f.paths === 0 && !f.patched)
    .forEach((f) => lines.push({ text: `[advise] ${f.cve} CVSS ${f.cvss}${f.kev ? " KEV" : ""} → 0 paths · deprioritize`, tone: "ok" }));
  scan.findings
    .filter((f) => f.tier === "auto" || f.tier === "approval")
    .forEach((f) =>
      lines.push({
        text: `[tier]   ${f.id} ${f.host.padEnd(8)} ${f.tier === "auto" ? "AUTO          " : "NEEDS APPROVAL"} · ${f.reason}`,
        tone: f.tier === "auto" ? "ok" : "warn",
      })
    );
  scan.findings
    .filter((f) => f.patched)
    .forEach((f) => lines.push({ text: `[fixed]  ${f.cve} on ${f.host} patched`, tone: "ok" }));
  lines.push({
    text: scan.paths.length === 0 ? "[done]   no attack paths remain" : "[done]   scan complete · fixes staged for review",
    tone: "info",
  });
  return lines;
}

const toneClass: Record<Line["tone"], string> = {
  cmd: "text-white",
  info: "text-sky-300",
  hit: "text-[#ff7a5c]",
  ok: "text-emerald-400",
  warn: "text-amber-300",
  muted: "text-white/45",
};

export default function ScanTerminal({ onRescan, onFinished, liveScan, label = "sample workspace" }: { onRescan: () => Promise<Scan | null>; onFinished?: () => void; liveScan?: Scan | null; label?: string }) {
  const [script, setScript] = useState<Line[]>([]);
  const [shown, setShown] = useState(0);
  const [loading, setLoading] = useState(false);
  const [started, setStarted] = useState(false);
  const running = started && shown < script.length;
  const bodyRef = useRef<HTMLDivElement>(null);
  const [logOpen, setLogOpen] = useState<boolean | null>(null); // null = automatic: open while scanning, folded when done

  useEffect(() => {
    if (!running) return;
    const t = window.setTimeout(() => setShown((n) => n + 1), shown === 0 ? 250 : 140);
    return () => window.clearTimeout(t);
  }, [running, shown]);

  useEffect(() => {
    bodyRef.current?.scrollTo({ top: bodyRef.current.scrollHeight, behavior: "smooth" });
  }, [shown]);

  const done = started && shown >= script.length;
  const busy = running || loading;

  const showLog = logOpen ?? !done;

  // When the replay ends, tell the page the scan is complete.
  useEffect(() => {
    if (done) onFinished?.();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [done]);

  const start = async () => {
    setLoading(true);
    const fresh = await onRescan(); // real scan against FalkorDB, then replay its results
    setLoading(false);
    if (!fresh) return;
    setScript(buildScript(fresh));
    setShown(0);
    setStarted(true);
    setLogOpen(null);
  };

  if (!started && !loading) {
    // First visit (or after a reset): one calm call to action instead of an empty terminal.
    return (
      <div id="scan" className="panel-sheen flex scroll-mt-20 flex-col items-start justify-between gap-6 rounded-3xl border border-line bg-panel p-7 sm:flex-row sm:items-center">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-widest text-muted">step 1 · scan</p>
          <h2 className="mt-2 text-2xl leading-tight tracking-tight sm:text-3xl">
            Ready to scan <em className="font-serif italic">{label === "sample workspace" ? "the sample workspace" : "your workspace"}</em>.
          </h2>
          <p className="mt-2 max-w-xl text-sm text-muted">
            Queries the FalkorDB graph, finds every route from the internet to your crown jewel, and ranks the findings by the paths they sit on.
          </p>
        </div>
        <button
          onClick={start}
          disabled={busy}
          className="btn-chrome flex h-12 shrink-0 items-center gap-2 rounded-full px-7 text-sm font-semibold transition disabled:opacity-60"
        >
          <Play className="h-4 w-4" /> Run scan
        </button>
      </div>
    );
  }

  return (
    <div id="scan" className="flex scroll-mt-20 flex-col overflow-hidden rounded-3xl border border-white/10 bg-[#050505]">
      <div className="flex items-center justify-between border-b border-white/10 px-4 py-2.5">
        <div className="flex items-center gap-2">
          <span className="h-2.5 w-2.5 rounded-full bg-danger/70" />
          <span className="h-2.5 w-2.5 rounded-full bg-warn/70" />
          <span className="h-2.5 w-2.5 rounded-full bg-ok/70" />
          <span className="ml-2 font-mono text-xs text-white/55">scan · {label}</span>
        </div>
        <button
          onClick={start}
          disabled={busy}
          className="flex items-center gap-1.5 rounded-full border border-white/20 bg-black/[0.06] px-3 py-1 font-mono text-xs text-white transition hover:bg-white/20 disabled:opacity-50"
        >
          {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : done ? <RotateCcw className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
          {loading ? "querying graph…" : running ? "scanning…" : done ? "re-run" : "run scan"}
        </button>
      </div>
      <div
        ref={bodyRef}
        className={`overflow-y-auto font-mono text-[12px] leading-6 ${started && showLog ? "h-[240px] p-4" : "px-4 py-3"}`}
      >
        {!started ? (
          <p className="text-white/55">
            Ready. Press <span className="text-accent">run scan</span> to query the FalkorDB graph.
            <span className="cursor-blink"> _</span>
          </p>
        ) : !showLog ? (
          <p className="flex flex-wrap items-center justify-between gap-2 text-white/55">
            <span className={(liveScan ? liveScan.paths.length > 0 : script.some((l) => l.tone === "hit")) ? "text-danger" : "text-ok"}>
              {liveScan
                ? `${liveScan.paths.length} attack ${liveScan.paths.length === 1 ? "path" : "paths"} to the crown jewel${liveScan.paths.length === 0 ? " · all clear" : ""}`
                : script.find((l) => l.text.startsWith("[paths]"))?.text.replace("[paths]", "").trim()}
            </span>
            <button onClick={() => setLogOpen(true)} className="underline underline-offset-2 hover:text-white">
              show log
            </button>
          </p>
        ) : (
          script.slice(0, shown).map((l, i) => (
            <div key={i} className={`whitespace-pre ${toneClass[l.tone]}`}>
              {l.text}
            </div>
          ))
        )}
        {running && <span className="cursor-blink text-accent">▋</span>}
      </div>
      {(!started || showLog) && (
        <div className="border-t border-white/10 px-4 py-2 font-mono text-[10px] text-white/55">
          live results · FalkorDB via FastAPI engine
        </div>
      )}
    </div>
  );
}
