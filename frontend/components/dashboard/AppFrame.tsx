"use client";

import Image from "next/image";
import Link from "next/link";
import { useEffect, useState, type ReactNode } from "react";
import { signOut } from "next-auth/react";
import { Activity, CreditCard, History, LayoutDashboard, LogOut, Menu, Network, Radar, Settings, ShieldCheck, X } from "lucide-react";
import type { Plan } from "@/lib/plans";

export interface FrameUser {
  name: string;
  email: string;
  image: string | null;
  plan: Plan;
}

const SECTIONS = [
  { href: "#overview", label: "Overview", icon: Activity },
  { href: "#graph", label: "Attack graph", icon: Network },
  { href: "#scan", label: "Scan", icon: Radar },
  { href: "#fix", label: "Fix queue", icon: ShieldCheck },
  { href: "#applied", label: "Applied fixes", icon: History },
] as const;

export function PlanBadge({ plan }: { plan: Plan }) {
  return (
    <span
      className={`rounded-md border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider ${
        plan === "pro" ? "border-accent/40 bg-accent/10 text-accent" : "border-line bg-black/[0.04] text-muted"
      }`}
    >
      {plan === "pro" ? "Pro" : "Basic"}
    </span>
  );
}

/** Sidebar + header shared by the dashboard and settings pages. */
export default function AppFrame({
  user,
  active,
  showSections = false,
  sidebarFooter,
  headerStatus,
  workspace = "sample",
  children,
}: {
  user: FrameUser;
  active: "dashboard" | "settings";
  showSections?: boolean;
  sidebarFooter?: ReactNode;
  headerStatus?: ReactNode;
  workspace?: string;
  children: ReactNode;
}) {
  const [drawer, setDrawer] = useState(false);
  useEffect(() => {
    if (!drawer) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setDrawer(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [drawer]);

  const top = [
    { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard, id: "dashboard" },
    { href: "/dashboard/settings", label: "Settings & billing", icon: Settings, id: "settings" },
    { href: "/pricing", label: "Pricing", icon: CreditCard, id: "pricing" },
  ] as const;

  const navList = (
      <nav className="flex-1 space-y-1 overflow-y-auto p-3">
        {top.map((n) => (
          <Link
            key={n.id}
            href={n.href}
            aria-current={active === n.id ? "page" : undefined}
            className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition ${
              active === n.id ? "bg-accent/10 text-accent" : "text-muted hover:bg-black/[0.04] hover:text-fg"
            }`}
          >
            <n.icon className="h-4 w-4" />
            {n.label}
          </Link>
        ))}
        {showSections && (
          <>
            <p className="px-3 pb-1 pt-4 font-mono text-[10px] uppercase tracking-widest text-muted/70">On this page</p>
            {SECTIONS.map((n) => (
              <a
                key={n.href}
                href={n.href}
                className="flex items-center gap-3 rounded-lg px-3 py-1.5 text-sm text-muted transition hover:bg-black/[0.04] hover:text-fg"
              >
                <n.icon className="h-4 w-4" />
                {n.label}
              </a>
            ))}
          </>
        )}
      </nav>
  );

  return (
    <div className="flex min-h-screen bg-bg">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-line bg-panel/60 lg:flex">
        <Link href="/dashboard" className="flex h-16 items-center gap-2 border-b border-line px-5 font-semibold">
          <span className="grid h-7 w-7 place-items-center rounded-lg border border-accent/30 bg-accent/10">
            <Radar className="h-3.5 w-3.5 text-accent" />
          </span>
          BlastRadius
        </Link>
        {navList}
        {sidebarFooter && <div className="border-t border-line p-3">{sidebarFooter}</div>}
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-line bg-bg/70 px-4 backdrop-blur-xl sm:px-6">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setDrawer(true)}
              className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-line bg-panel text-muted transition hover:text-fg lg:hidden"
              aria-label="Open menu"
              aria-expanded={drawer}
            >
              <Menu className="h-4 w-4" />
            </button>
            <span className="hidden whitespace-nowrap rounded-md border border-line bg-panel px-2 py-1 font-mono text-xs text-muted sm:inline">
              workspace / <span className="text-fg">{workspace}</span>
            </span>
            {headerStatus}
          </div>
          <div className="flex items-center gap-3">
            <Link href="/dashboard/settings" aria-label="Your plan">
              <PlanBadge plan={user.plan} />
            </Link>
            <div className="hidden text-right sm:block">
              <div className="text-sm">{user.name}</div>
              <div className="text-xs text-muted">{user.email}</div>
            </div>
            {user.image && (
              <Image src={user.image} alt={user.name} width={32} height={32} className="rounded-full border border-line" unoptimized />
            )}
            <button
              onClick={() => signOut({ callbackUrl: "/" })}
              className="grid h-9 w-9 place-items-center rounded-lg text-muted transition hover:bg-panel hover:text-fg"
              aria-label="Sign out"
              title="Sign out"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </header>
        {drawer && (
          <div className="fixed inset-0 z-50 lg:hidden" role="dialog" aria-modal="true" aria-label="Menu">
            <button className="absolute inset-0 bg-black/40" aria-label="Close menu" onClick={() => setDrawer(false)} />
            <div className="absolute left-0 top-0 flex h-full w-72 max-w-[85vw] flex-col border-r border-line bg-bg shadow-2xl" onClick={(e) => (e.target as HTMLElement).closest("a, button") && setDrawer(false)}>
              <div className="flex h-16 items-center justify-between border-b border-line px-5 font-semibold">
                <span className="flex items-center gap-2">
                  <span className="grid h-7 w-7 place-items-center rounded-lg border border-accent/30 bg-accent/10">
                    <Radar className="h-3.5 w-3.5 text-accent" />
                  </span>
                  BlastRadius
                </span>
                <button className="grid h-9 w-9 place-items-center rounded-lg text-muted hover:bg-panel hover:text-fg" aria-label="Close menu">
                  <X className="h-4 w-4" />
                </button>
              </div>
              {navList}
              {sidebarFooter && <div className="border-t border-line p-3">{sidebarFooter}</div>}
            </div>
          </div>
        )}
        <main className="console-bg relative flex-1">{children}</main>
      </div>
    </div>
  );
}
