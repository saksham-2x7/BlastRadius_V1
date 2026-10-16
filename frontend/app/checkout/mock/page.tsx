import type { Metadata } from "next";
import { Suspense } from "react";
import Layout from "@/components/layout/Layout";
import MockCheckout from "@/components/billing/MockCheckout";

export const metadata: Metadata = { title: "Checkout · BlastRadius", robots: { index: false } };

export default function MockCheckoutPage() {
  return (
    <Layout>
      <section className="px-4 pb-24 pt-32 sm:px-6">
        <Suspense fallback={<div className="mx-auto h-[420px] max-w-4xl animate-pulse rounded-3xl border border-line bg-panel" />}>
          <MockCheckout />
        </Suspense>
      </section>
    </Layout>
  );
}
