"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";
import { useSession } from "next-auth/react";
import { Check, Loader2, Lock, Radar } from "lucide-react";
import { PLANS } from "@/lib/plans";

/** Simulated hosted checkout. The card fields are display-only: nothing typed here is read or sent anywhere. */
export default function MockCheckout() {
  const token = useSearchParams().get("token");
  const router = useRouter();
  const { update } = useSession();
  const [paying, setPaying] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const pro = PLANS.pro;

  const pay = async () => {
    if (!token) return;
    setPaying(true);
    setError(null);
    try {
      await new Promise((r) => setTimeout(r, 900)); // feel of a real payment round-trip
      const res = await fetch("/api/checkout/mock/complete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      });
      const body = (await res.json().catch(() => null)) as { message?: string } | null;
      if (!res.ok) {
        setError(body?.message ?? "Payment could not be completed.");
        setPaying(false);
        return;
      }
      await update(); // refresh the session so the new plan shows immediately
      router.push("/dashboard/settings?checkout=success");
    } catch {
      setError("Network error. Please try again.");
      setPaying(false);
    }
  };

  if (!token) {
    return (
      <div className="mx-auto max-w-md rounded-2xl border border-line bg-panel p-8 text-center">
        <p className="text-sm text-muted">This checkout link is missing its token.</p>
        <Link href="/pricing" className="mt-4 inline-block text-sm text-accent underline">
          Back to pricing
        </Link>
      </div>
    );
  }

  return (
    <div className="mx-auto grid max-w-4xl overflow-hidden rounded-3xl border border-line bg-panel md:grid-cols-2">
      <div className="border-b border-line bg-gradient-to-br from-accent/10 to-transparent p-8 md:border-b-0 md:border-r">
        <div className="flex items-center gap-2 text-sm text-muted">
          <span className="grid h-7 w-7 place-items-center rounded-lg border border-accent/30 bg-accent/10">
            <Radar className="h-3.5 w-3.5 text-accent" />
          </span>
          BlastRadius
        </div>
        <p className="mt-8 text-sm text-muted">Subscribe to {pro.name}</p>
        <p className="mt-1 text-4xl font-semibold tracking-tight">
          {pro.price}.00 <span className="text-base font-normal text-muted">/ month</span>
        </p>
        <ul className="mt-6 space-y-2 text-sm text-fg/90">
          {pro.features.filter((f) => f.included && !f.soon).map((f) => (
            <li key={f.text} className="flex items-start gap-2">
              <Check className="mt-0.5 h-4 w-4 shrink-0 text-accent" />
              {f.text}
            </li>
          ))}
        </ul>
      </div>

      <div className="p-8">
        <div className="mb-5 rounded-lg border border-warn/30 bg-warn/10 px-3 py-2 font-mono text-xs text-warn">
          Simulated checkout. No real payment, no card data collected.
        </div>
        <div className="space-y-3">
          {[
            ["Card number", "4242 4242 4242 4242"],
            ["Expiry", "12 / 34"],
            ["CVC", "•••"],
          ].map(([label, value]) => (
            <label key={label} className="block">
              <span className="mb-1 block text-xs text-muted">{label}</span>
              <input
                value={value}
                readOnly
                tabIndex={-1}
                className="h-10 w-full cursor-not-allowed rounded-lg border border-line bg-bg px-3 font-mono text-sm text-muted"
              />
            </label>
          ))}
        </div>
        <button
          onClick={pay}
          disabled={paying}
          className="mt-6 flex h-11 w-full items-center justify-center gap-2 rounded-full btn-chrome text-sm font-semibold transition disabled:opacity-60"
        >
          {paying ? <Loader2 className="h-4 w-4 animate-spin" /> : <Lock className="h-4 w-4" />}
          {paying ? "Processing…" : `Pay ${pro.price}.00`}
        </button>
        {error && (
          <p role="alert" className="mt-3 text-sm text-danger">
            {error}
          </p>
        )}
        <Link href="/pricing" className="mt-4 block text-center text-sm text-muted transition hover:text-fg">
          Cancel and go back
        </Link>
      </div>
    </div>
  );
}
