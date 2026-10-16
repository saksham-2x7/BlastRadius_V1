import type { Metadata } from "next";
import { Suspense } from "react";
import { redirect } from "next/navigation";
import AppFrame from "@/components/dashboard/AppFrame";
import SettingsView from "@/components/dashboard/SettingsView";
import { currentUser } from "@/lib/session";
import { getAccount } from "@/lib/subscription";
import { billingMode } from "@/lib/stripe";

export const metadata: Metadata = { title: "Settings · BlastRadius" };

async function Settings({ searchParams }: { searchParams: Promise<{ checkout?: string; plan?: string }> }) {
  const user = await currentUser();
  if (!user) redirect("/");
  const sp = await searchParams;
  // Fail closed to Basic if the engine is unreachable: the page still renders and nothing is granted.
  const account = await getAccount(user.id).catch(() => null);
  const plan = account?.plan ?? "free";

  return (
    <AppFrame user={{ name: user.name, email: user.email, image: user.image, plan }} active="settings">
      <SettingsView
        data={{
          id: user.id,
          name: user.name,
          email: user.email,
          image: user.image,
          provider: user.provider,
          plan,
          hasCustomer: !!account?.customer_id,
          mock: billingMode === "mock",
          notice: sp.checkout === "success" && plan === "pro" ? "success" : sp.plan === "cancelled" ? "cancelled" : null,
        }}
      />
    </AppFrame>
  );
}

function SettingsLoading() {
  return (
    <div className="flex min-h-screen bg-bg">
      <div className="hidden w-60 shrink-0 border-r border-line bg-panel/60 lg:block" />
      <div className="mx-auto w-full max-w-3xl space-y-4 p-6">
        {[140, 220, 150].map((h) => (
          <div key={h} style={{ height: h }} className="animate-pulse rounded-2xl border border-line bg-panel" />
        ))}
      </div>
    </div>
  );
}

export default function SettingsPage({ searchParams }: { searchParams: Promise<{ checkout?: string; plan?: string }> }) {
  return (
    <Suspense fallback={<SettingsLoading />}>
      <Settings searchParams={searchParams} />
    </Suspense>
  );
}
