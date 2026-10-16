"use client";

import Link from "next/link";
import Image from "next/image";
import { useEffect, useState } from "react";
import { signIn, signOut, useSession } from "next-auth/react";
import { motion } from "framer-motion";
import { LayoutDashboard, LogOut, Menu, Radar, X } from "lucide-react";
import GoogleIcon from "@/components/ui/GoogleIcon";

const LINKS = [
  { href: "/#how", label: "How it works" },
  { href: "/#why", label: "Why paths" },
  { href: "/#autofix", label: "Safe autofix" },
  { href: "/#pricing", label: "Pricing" },
];

export default function Navbar() {
  const { data: session, status } = useSession();
  const [scrolled, setScrolled] = useState(false);
  const [menu, setMenu] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <motion.header
      initial={{ y: -24, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.5, ease: "easeOut" }}
      className={`fixed inset-x-0 top-0 z-50 transition-colors duration-300 ${
        scrolled ? "border-b border-line bg-bg/75 backdrop-blur-xl" : "bg-transparent"
      }`}
    >
      <nav className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6">
        <Link href="/" className="flex items-center gap-2 font-semibold tracking-tight">
          <span className="grid h-8 w-8 place-items-center rounded-lg border border-accent/30 bg-accent/10">
            <Radar className="h-4 w-4 text-accent" />
          </span>
          BlastRadius
        </Link>

        <div className="hidden items-center gap-8 text-sm text-muted md:flex">
          {LINKS.map((l) => (
            <Link key={l.label} href={l.href} className="transition-colors hover:text-fg">
              {l.label}
            </Link>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <button
            className="grid h-9 w-9 place-items-center rounded-lg border border-line bg-panel md:hidden"
            aria-label={menu ? "Close menu" : "Open menu"}
            aria-expanded={menu}
            onClick={() => setMenu((m) => !m)}
          >
            {menu ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
          </button>
          {status === "loading" ? (
            <div className="h-9 w-40 animate-pulse rounded-lg bg-panel-2" />
          ) : session ? (
            <>
              <Link
                href="/dashboard"
                className="hidden items-center gap-2 rounded-lg border border-line bg-panel px-3 py-2 text-sm transition hover:border-accent/40 sm:flex"
              >
                <LayoutDashboard className="h-4 w-4 text-accent" />
                Dashboard
              </Link>
              {session.user?.image && (
                <Image
                  src={session.user.image}
                  alt={session.user.name ?? "Account"}
                  width={32}
                  height={32}
                  className="rounded-full border border-line"
                  unoptimized
                />
              )}
              <button
                onClick={() => signOut({ callbackUrl: "/" })}
                className="grid h-9 w-9 place-items-center rounded-lg text-muted transition hover:bg-panel hover:text-fg"
                aria-label="Sign out"
              >
                <LogOut className="h-4 w-4" />
              </button>
            </>
          ) : (
            <button
              onClick={() => signIn("google", { callbackUrl: "/dashboard" })}
              className="group flex items-center gap-2 rounded-full border border-line bg-black/[0.04] px-4 py-2 text-sm font-medium transition hover:border-black/30 hover:bg-black/[0.07]"
            >
              <GoogleIcon />
              Sign in with Google
            </button>
          )}
        </div>
      </nav>
      {menu && (
        <div className="border-t border-line bg-bg px-4 pb-4 pt-2 md:hidden">
          {LINKS.map((l) => (
            <Link key={l.label} href={l.href} onClick={() => setMenu(false)} className="block border-b border-line py-3 text-base text-fg">
              {l.label}
            </Link>
          ))}
        </div>
      )}
    </motion.header>
  );
}
