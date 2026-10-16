import type { Metadata } from "next";
import { Suspense } from "react";
import { redirect } from "next/navigation";
import { getServerSession } from "next-auth";
import { Radar } from "lucide-react";
import { authOptions } from "@/lib/auth";
import { getAccount } from "@/lib/subscription";
import { billingMode } from "@/lib/stripe";
import { EngineError, engineFetch, type Scan } from "@/lib/engine";
import { workspaceHeaders } from "@/lib/workspace";
import DashboardShell, { type Initial } from "@/components/dashboard/DashboardShell";

export const metadata: Metadata = { title: "Dashboard · BlastRadius", robots: { index: false, follow: false } };

// Reads the session cookie and the live engine, so it renders inside <Suspense> (cacheComponents is on).
async function AuthedDashboard() {
  const session = await getServerSession(authOptions);
  if (!session?.user) redirect("/");

  let initial: Initial;
  try {
    initial = { scan: await engineFetch<Scan>("/api/scan", { headers: await workspaceHeaders(session.user.id) }) };
  } catch (err) {
    initial = {
      error:
        err instanceof EngineError
          ? err.info
          : { kind: "unknown", status: 500, message: "Unexpected error while scanning." },
    };
  }

  // The plan shown here is read fresh from the database (Basic if it can't be read); the server re-checks it on every Pro action.
  const plan = await getAccount(session.user.id).then((a) => a.plan).catch(() => "free" as const);

  return (
    <DashboardShell
      user={{
        name: session.user.name ?? "Analyst",
        email: session.user.email ?? "",
        image: session.user.image ?? null,
        plan,
      }}
      initial={initial}
      mock={billingMode === "mock"}
    />
  );
}

function DashboardLoading() {
  return (
    <div className="flex min-h-screen bg-bg">
      <div className="hidden w-60 shrink-0 border-r border-line bg-panel/60 lg:block" />
      <div className="flex-1 space-y-4 p-4 sm:p-6">
        <div className="flex items-center gap-2 font-mono text-sm text-accent">
          <Radar className="h-4 w-4 animate-spin [animation-duration:2s]" />
          scanning graph<span className="cursor-blink">_</span>
        </div>
        <div className="grid grid-cols-2 gap-3 xl:grid-cols-5">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="h-[84px] animate-pulse rounded-2xl border border-line bg-panel" />
          ))}
        </div>
        <div className="grid gap-4 xl:grid-cols-5">
          <div className="h-[480px] animate-pulse rounded-2xl border border-line bg-panel xl:col-span-3" />
          <div className="h-[480px] animate-pulse rounded-2xl border border-line bg-panel xl:col-span-2" />
        </div>
      </div>
    </div>
  );
}

export default function DashboardPage() {
  return (
    <Suspense fallback={<DashboardLoading />}>
      <AuthedDashboard />
    </Suspense>
  );
}
