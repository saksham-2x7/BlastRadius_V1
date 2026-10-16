"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { signIn, useSession } from "next-auth/react";
import { Loader2, Radar } from "lucide-react";
import GoogleIcon from "@/components/ui/GoogleIcon";

/** Entry point for outside links (e.g. the Framer landing page): starts Google sign-in, or goes straight to the dashboard. */
export default function LoginRedirect() {
  const { status } = useSession();
  const router = useRouter();

  useEffect(() => {
    if (status === "authenticated") router.replace("/dashboard");
    else if (status === "unauthenticated") void signIn("google", { callbackUrl: "/dashboard" });
  }, [status, router]);

  return (
    <main className="grid min-h-screen place-items-center bg-bg px-4">
      <div className="w-full max-w-sm rounded-2xl border border-line bg-panel p-8 text-center">
        <span className="mx-auto grid h-10 w-10 place-items-center rounded-xl border border-accent/30 bg-accent/10">
          <Radar className="h-5 w-5 text-accent" />
        </span>
        <h1 className="mt-4 text-lg font-medium">Signing you in</h1>
        <p className="mt-1 flex items-center justify-center gap-2 text-sm text-muted">
          <Loader2 className="h-4 w-4 animate-spin" /> Taking you to Google…
        </p>
        <button
          onClick={() => signIn("google", { callbackUrl: "/dashboard" })}
          className="mt-6 flex w-full items-center justify-center gap-2 rounded-lg border border-line bg-white/[0.04] px-3.5 py-2.5 text-sm font-medium transition hover:border-accent/50 hover:bg-white/[0.08]"
        >
          <GoogleIcon /> Continue with Google
        </button>
        <p className="mt-3 text-xs text-muted">Nothing happening? Click the button above.</p>
      </div>
    </main>
  );
}
