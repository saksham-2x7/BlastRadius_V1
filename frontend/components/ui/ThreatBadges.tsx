import { Flame } from "lucide-react";

export const fmtEpss = (epss: number) => (epss < 0.01 ? "<1%" : `${Math.round(epss * 100)}%`);

/** Glowing red marker for findings in the CISA Known Exploited Vulnerabilities catalog. */
export function KevBadge({ className = "" }: { className?: string }) {
  return (
    <span
      title="Listed in CISA KEV: exploited in the wild"
      className={`kev-glow inline-flex items-center gap-1 rounded border border-danger/60 bg-danger/20 px-1.5 py-px font-mono text-[10px] font-semibold text-danger ${className}`}
    >
      <Flame className="h-2.5 w-2.5" aria-hidden />
      KEV
    </span>
  );
}

/** EPSS exploit probability as a percentage with a small meter. */
export function EpssMeter({ epss }: { epss: number }) {
  const tone = epss >= 0.5 ? "bg-danger text-danger" : epss >= 0.1 ? "bg-warn text-warn" : "bg-slate-500 text-muted";
  const [bar, text] = tone.split(" ");
  return (
    <span
      className="flex items-center gap-1.5 font-mono text-[11px]"
      title={`EPSS: ${(epss * 100).toFixed(1)}% probability of exploitation in the next 30 days (FIRST EPSS)`}
    >
      <span className="text-muted">EPSS</span>
      <span className={text}>{fmtEpss(epss)}</span>
      <span className="h-1 w-10 overflow-hidden rounded-full bg-black/[0.06]" aria-hidden>
        <span className={`block h-full rounded-full ${bar}`} style={{ width: `${Math.max(3, Math.round(epss * 100))}%` }} />
      </span>
    </span>
  );
}
