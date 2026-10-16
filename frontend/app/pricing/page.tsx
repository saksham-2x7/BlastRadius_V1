import type { Metadata } from "next";
import { Suspense } from "react";
import { connection } from "next/server";
import Layout from "@/components/layout/Layout";
import PlanCards from "@/components/pricing/PlanCards";
import { billingMode } from "@/lib/stripe";

export const metadata: Metadata = {
  title: "Pricing · BlastRadius",
  description: "Start free. Upgrade to Pro to clear every safe fix in one click.",
  alternates: { canonical: "/pricing" },
};

// Billing mode comes from runtime env, so render at request time rather than baking it into the build.
async function Cards() {
  await connection();
  return <PlanCards mock={billingMode === "mock"} />;
}

export default function PricingPage() {
  return (
    <Layout>
      <section className="mx-auto max-w-7xl px-4 pb-24 pt-32 sm:px-6">
        <div className="mx-auto max-w-2xl text-center">
          <p className="font-mono text-xs uppercase tracking-[0.2em] text-accent">Pricing</p>
          <h1 className="mt-3 text-4xl font-semibold tracking-tight sm:text-5xl">Simple pricing. <em className="font-serif font-normal italic text-accent">Safe by default.</em></h1>
          <p className="mt-4 text-muted">
            Every plan finds your real attack paths. Pro adds one click to clear every safe fix.
          </p>
        </div>
        <div className="mt-14">
          <Suspense fallback={<div className="mx-auto h-[420px] max-w-4xl animate-pulse rounded-2xl border border-line bg-panel" />}>
            <Cards />
          </Suspense>
        </div>
      </section>
    </Layout>
  );
}
