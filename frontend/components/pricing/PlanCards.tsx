"use client";

import Link from "next/link";
import { useState } from "react";
import { signIn, useSession } from "next-auth/react";
import { Check, Loader2, Minus, ShieldCheck, Sparkles } from "lucide-react";
import { PLANS, type Plan } from "@/lib/plans";

/** Starts checkout for Pro (or sends signed-out visitors through Google sign-in first). */
export function useUpgrade() {
  const { data: session, status } = useSession();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const upgrade = async () => {
    if (!session) {
      await signIn("google", { callbackUrl: "/pricing" });
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/checkout", { method: "POST" });
      const body = (await res.json().catch(() => null)) as { url?: string; message?: string } | null;
      if (!res.ok || !body?.url) {
        setError(body?.message ?? "Could not start checkout. Please try again.");
        setLoading(false);
        return;
      }
      window.location.assign(body.url);
    } catch {
      setError("Network error. Please try again.");
      setLoading(false);
    }
  };

  const plan: Plan = session?.user.plan ?? "free";
  return { upgrade, loading, error, plan, signedIn: !!session, ready: status !== "loading" };
}

export default function PlanCards({ mock, compact = false }: { mock: boolean; compact?: boolean }) {
  const { upgrade, loading, error, plan, signedIn, ready } = useUpgrade();

  return (
    <div>
      <div className={`grid gap-4 ${compact ? "md:grid-cols-2" : "mx-auto max-w-4xl md:grid-cols-2"}`}>
        {(["free", "pro"] as const).map((id) => {
          const p = PLANS[id];
          const pro = id === "pro";
          const isCurrent = ready && signedIn && plan === id;
          return (
            <div
              key={id}
              className={`relative flex flex-col rounded-2xl border p-6 ${
                pro
                  ? "border-accent/40 bg-gradient-to-b from-accent/10 to-panel shadow-[0_40px_80px_-40px_rgba(13,13,15,0.35)]"
                  : "border-line bg-panel"
              }`}
            >
              {pro && (
                <span className="absolute -top-3 left-6 flex items-center gap-1 rounded-full border border-accent/40 bg-bg px-2.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-accent">
                  <Sparkles className="h-3 w-3" /> Recommended
                </span>
              )}
              <h3 className="text-lg font-medium">{p.name}</h3>
              <div className="mt-3 flex items-baseline gap-2">
                <span className="text-4xl font-semibold tracking-tight">{p.price}</span>
                <span className="text-sm text-muted">{p.period}</span>
              </div>
              <p className="mt-2 text-sm text-muted">{p.blurb}</p>

              <ul className="mt-5 flex-1 space-y-2.5 text-sm">
                {p.features.map((f) => (
                  <li key={f.text} className={`flex items-start gap-2.5 ${f.included ? "text-fg/90" : "text-muted/60"}`}>
                    {f.included ? (
                      <Check className="mt-0.5 h-4 w-4 shrink-0 text-accent" />
                    ) : (
                      <Minus className="mt-0.5 h-4 w-4 shrink-0" />
                    )}
                    <span className={f.included ? "" : "line-through decoration-muted/40"}>
                      {f.text}
                      {f.soon && (
                        <span className="ml-2 rounded border border-line px-1.5 py-0.5 font-mono text-[9px] uppercase text-muted">
                          soon
                        </span>
                      )}
                    </span>
                  </li>
                ))}
              </ul>

              <div className="mt-6">
                {isCurrent ? (
                  <div className="flex h-11 items-center justify-center gap-2 rounded-xl border border-line bg-black/[0.04] text-sm text-muted">
                    <ShieldCheck className="h-4 w-4 text-ok" /> Current plan
                  </div>
                ) : pro ? (
                  <button
                    onClick={upgrade}
                    disabled={loading || !ready}
                    className="flex h-11 w-full items-center justify-center gap-2 rounded-full btn-chrome text-sm font-semibold transition disabled:opacity-60"
                  >
                    {loading && <Loader2 className="h-4 w-4 animate-spin" />}
                    {loading ? "Opening checkout…" : signedIn ? "Upgrade to Pro" : "Sign in to upgrade"}
                  </button>
                ) : (
                  <Link
                    href="/dashboard"
                    className="flex h-11 items-center justify-center rounded-xl border border-line text-sm transition hover:border-accent/40 hover:bg-black/[0.04]"
                  >
                    {signedIn ? "Go to dashboard" : "Start free"}
                  </Link>
                )}
              </div>
            </div>
          );
        })}
      </div>
      {error && (
        <p role="alert" className="mt-4 text-center text-sm text-danger">
          {error}
        </p>
      )}
      {mock && (
        <p className="mt-4 text-center font-mono text-xs text-muted">
          Test mode: checkout is simulated. No real payment is taken.
        </p>
      )}
    </div>
  );
}
