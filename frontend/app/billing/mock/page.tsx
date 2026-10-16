"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { useSession } from "next-auth/react";
import { Loader2, Radar } from "lucide-react";
import Layout from "@/components/layout/Layout";
import { PlanBadge } from "@/components/dashboard/AppFrame";
import { PLANS } from "@/lib/plans";

/** Stand-in for Stripe's Billing Portal (mock billing mode only). */
export default function MockBillingPortal() {
  const { data: session, update } = useSession();
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const plan = session?.user.plan ?? "free";

  const cancel = async () => {
    setBusy(true);
    setError(null);
    const res = await fetch("/api/billing/cancel", { method: "POST" }).catch(() => null);
    if (!res?.ok) {
      const body = await res?.json().catch(() => null);
      setError(body?.message ?? "Could not cancel. Please try again.");
      setBusy(false);
      return;
    }
    await update();
    router.push("/dashboard/settings?plan=cancelled");
  };

  return (
    <Layout>
      <section className="px-4 pb-24 pt-32 sm:px-6">
        <div className="mx-auto max-w-lg rounded-3xl border border-line bg-panel p-8">
          <div className="flex items-center gap-2 text-sm text-muted">
            <span className="grid h-7 w-7 place-items-center rounded-lg border border-accent/30 bg-accent/10">
              <Radar className="h-3.5 w-3.5 text-accent" />
            </span>
            Billing portal
          </div>
          <div className="mt-4 rounded-lg border border-warn/30 bg-warn/10 px-3 py-2 font-mono text-xs text-warn">
            Simulated portal. With Stripe keys set this opens Stripe&apos;s real Billing Portal.
          </div>
          <div className="mt-6 flex items-center justify-between rounded-xl border border-line bg-bg p-4">
            <div>
              <p className="text-sm text-muted">Current plan</p>
              <p className="mt-1 font-medium">
                {PLANS[plan].name} · {PLANS[plan].price} {plan === "pro" ? "/ month" : ""}
              </p>
            </div>
            <PlanBadge plan={plan} />
          </div>
          {error && (
            <p role="alert" className="mt-3 text-sm text-danger">
              {error}
            </p>
          )}
          <div className="mt-6 flex flex-col gap-3 sm:flex-row">
            {plan === "pro" ? (
              <button
                onClick={cancel}
                disabled={busy}
                className="flex h-11 flex-1 items-center justify-center gap-2 rounded-xl border border-danger/40 bg-danger/10 text-sm text-danger transition hover:bg-danger/20 disabled:opacity-60"
              >
                {busy && <Loader2 className="h-4 w-4 animate-spin" />}
                Cancel subscription
              </button>
            ) : (
              <Link href="/pricing" className="flex h-11 flex-1 items-center justify-center rounded-full btn-chrome text-sm font-semibold transition">
                Upgrade to Pro
              </Link>
            )}
            <Link href="/dashboard/settings" className="flex h-11 flex-1 items-center justify-center rounded-xl border border-line text-sm transition hover:border-accent/40 hover:bg-black/[0.04]">
              Back to settings
            </Link>
          </div>
        </div>
      </section>
    </Layout>
  );
}
