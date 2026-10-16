"use client";

import Image from "next/image";
import Link from "next/link";
import { useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { motion } from "framer-motion";
import { Check, CreditCard, ExternalLink, Loader2, Minus, PartyPopper, UserRound } from "lucide-react";
import { PlanBadge } from "./AppFrame";
import { useUpgrade } from "@/components/pricing/PlanCards";
import { PLANS, type Plan } from "@/lib/plans";

export interface SettingsData {
  id: string;
  name: string;
  email: string;
  image: string | null;
  provider: string | null;
  plan: Plan;
  hasCustomer: boolean;
  mock: boolean;
  notice: "success" | "cancelled" | null;
}

function Card({ title, icon: Icon, children }: { title: string; icon: typeof UserRound; children: React.ReactNode }) {
  return (
    <section className="rounded-2xl border border-line bg-panel">
      <h2 className="flex items-center gap-2 border-b border-line px-5 py-3.5 text-sm font-medium">
        <Icon className="h-4 w-4 text-accent" /> {title}
      </h2>
      <div className="p-5">{children}</div>
    </section>
  );
}

export default function SettingsView({ data }: { data: SettingsData }) {
  const { update } = useSession();
  const { upgrade, loading: upgrading, error: upgradeError } = useUpgrade();
  const [portalBusy, setPortalBusy] = useState(false);
  const [portalError, setPortalError] = useState<string | null>(null);
  const plan = PLANS[data.plan];
  const providerName = data.provider ? data.provider.charAt(0).toUpperCase() + data.provider.slice(1) : "Google"; // sessions from before the provider was recorded were all Google

  // After a checkout / cancellation, refresh the cookie session so the badge and gating match the database.
  useEffect(() => {
    if (data.notice) void update();
  }, [data.notice, update]);

  const openPortal = async () => {
    setPortalBusy(true);
    setPortalError(null);
    try {
      const res = await fetch("/api/billing/portal", { method: "POST" });
      const body = (await res.json().catch(() => null)) as { url?: string; message?: string } | null;
      if (!res.ok || !body?.url) {
        setPortalError(body?.message ?? "Could not open the billing portal.");
        setPortalBusy(false);
        return;
      }
      window.location.assign(body.url);
    } catch {
      setPortalError("Network error. Please try again.");
      setPortalBusy(false);
    }
  };

  return (
    <div className="mx-auto max-w-3xl space-y-4 p-4 sm:p-6">
      <div>
        <h1 className="text-3xl tracking-tight sm:text-4xl">Your <em className="font-serif italic">plan</em> &amp; billing</h1>
        <p className="mt-1 text-sm text-muted">Profile, plan and test-mode billing.</p>
      </div>

      {data.notice === "success" && (
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          role="status"
          className="flex items-center gap-3 rounded-xl border border-ok/30 bg-ok/10 px-4 py-3 text-sm text-ok"
        >
          <PartyPopper className="h-4 w-4" /> You&apos;re on Pro. &quot;Auto-fix all safe&quot; is now unlocked.
        </motion.div>
      )}
      {data.notice === "cancelled" && (
        <div role="status" className="rounded-xl border border-warn/30 bg-warn/10 px-4 py-3 text-sm text-warn">
          Your subscription was cancelled. You&apos;re back on Basic.
        </div>
      )}

      <Card title="Profile" icon={UserRound}>
        <div className="flex items-center gap-4">
          {data.image ? (
            <Image src={data.image} alt={data.name} width={56} height={56} className="rounded-full border border-line" unoptimized />
          ) : (
            <span className="grid h-14 w-14 place-items-center rounded-full border border-line bg-panel-2 text-lg">
              {data.name.charAt(0).toUpperCase()}
            </span>
          )}
          <div className="min-w-0">
            <p className="truncate font-medium">{data.name}</p>
            <p className="truncate text-sm text-muted">{data.email}</p>
          </div>
        </div>
        <dl className="mt-5 grid gap-3 text-sm sm:grid-cols-2">
          <div>
            <dt className="text-xs text-muted">Sign-in method</dt>
            <dd className="mt-0.5">{providerName}</dd>
          </div>
          <div>
            <dt className="text-xs text-muted">Account ID</dt>
            <dd className="mt-0.5 font-mono text-xs">…{data.id.slice(-8)}</dd>
          </div>
        </dl>
        <p className="mt-4 text-xs text-muted">Profile details come from your {providerName} account and can&apos;t be edited here.</p>
      </Card>

      <Card title="Plan" icon={Check}>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-lg font-medium">{plan.name}</span>
              <PlanBadge plan={data.plan} />
            </div>
            <p className="mt-1 text-sm text-muted">
              {plan.price} {data.plan === "pro" ? "per month" : "forever"}
            </p>
          </div>
          {data.plan === "free" && (
            <button
              onClick={upgrade}
              disabled={upgrading}
              className="flex h-10 items-center gap-2 rounded-full btn-chrome px-4 text-sm font-semibold transition disabled:opacity-60"
            >
              {upgrading && <Loader2 className="h-4 w-4 animate-spin" />}
              Upgrade to Pro
            </button>
          )}
        </div>
        <ul className="mt-5 space-y-2 text-sm">
          {plan.features.map((f) => (
            <li key={f.text} className={`flex items-start gap-2.5 ${f.included ? "text-fg/90" : "text-muted/60"}`}>
              {f.included ? <Check className="mt-0.5 h-4 w-4 shrink-0 text-accent" /> : <Minus className="mt-0.5 h-4 w-4 shrink-0" />}
              <span className={f.included ? "" : "line-through decoration-muted/40"}>{f.text}</span>
            </li>
          ))}
        </ul>
        {upgradeError && (
          <p role="alert" className="mt-3 text-sm text-danger">
            {upgradeError}
          </p>
        )}
      </Card>

      <Card title="Billing" icon={CreditCard}>
        <p className="text-sm text-muted">
          {data.mock
            ? "Billing is running in test mode: checkout and the portal are simulated and no payment is taken."
            : "Payments are handled securely by Stripe."}
        </p>
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <button
            onClick={openPortal}
            disabled={portalBusy || (!data.mock && !data.hasCustomer)}
            className="flex h-10 items-center gap-2 rounded-xl border border-line px-4 text-sm transition hover:border-accent/40 hover:bg-black/[0.04] disabled:cursor-not-allowed disabled:opacity-50"
          >
            {portalBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : <ExternalLink className="h-4 w-4" />}
            Manage billing
          </button>
          <Link href="/pricing" className="text-sm text-muted underline-offset-4 transition hover:text-fg hover:underline">
            Compare plans
          </Link>
        </div>
        {!data.mock && !data.hasCustomer && (
          <p className="mt-3 text-xs text-muted">The billing portal opens after your first upgrade.</p>
        )}
        {portalError && (
          <p role="alert" className="mt-3 text-sm text-danger">
            {portalError}
          </p>
        )}
      </Card>
    </div>
  );
}
