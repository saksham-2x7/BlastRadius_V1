"use client";

import { AlertTriangle, DatabaseZap, Loader2, RefreshCw, ServerCrash } from "lucide-react";
import type { EngineErrorInfo } from "@/lib/engine";

const COPY = {
  engine_unavailable: {
    icon: DatabaseZap,
    title: "FalkorDB is unreachable",
    hint: "The engine is up, but the graph database isn't. Start FalkorDB and retry.",
    cmd: "docker run -p 6379:6379 -p 3001:3000 falkordb/falkordb",
  },
  api_unreachable: {
    icon: ServerCrash,
    title: "Engine API is not running",
    hint: "The Python FastAPI service isn't responding. Start it from the backend folder and retry.",
    cmd: "cd backend && .venv/bin/uvicorn main:app --port 8000",
  },
  unauthorized: { icon: AlertTriangle, title: "Session expired", hint: "Sign in again to continue.", cmd: "" },
  rejected: { icon: AlertTriangle, title: "Fix rejected", hint: "", cmd: "" },
  upgrade_required: { icon: AlertTriangle, title: "Pro feature", hint: "Upgrade to Pro to use this.", cmd: "" },
  unknown: { icon: AlertTriangle, title: "Something went wrong", hint: "", cmd: "" },
} as const;

export default function EngineError({
  error,
  onRetry,
  retrying,
}: {
  error: EngineErrorInfo;
  onRetry: () => void;
  retrying: boolean;
}) {
  const c = COPY[error.kind];
  const Icon = c.icon;
  return (
    <div className="mx-auto mt-10 max-w-xl overflow-hidden rounded-2xl border border-danger/30 bg-gradient-to-b from-danger/10 to-panel">
      <div className="flex items-center gap-3 border-b border-danger/20 px-5 py-4">
        <span className="grid h-10 w-10 place-items-center rounded-xl border border-danger/30 bg-danger/10">
          <Icon className="h-5 w-5 text-danger" />
        </span>
        <div>
          <h2 className="font-medium">{c.title}</h2>
          <p className="font-mono text-xs text-danger/80">
            {error.status} · {error.kind}
            {error.host ? ` · ${error.host}:${error.port}` : ""}
          </p>
        </div>
      </div>
      <div className="space-y-4 px-5 py-4 text-sm">
        <p className="text-muted">{error.message}</p>
        {c.hint && <p className="text-fg/80">{c.hint}</p>}
        {c.cmd && (
          <code className="block overflow-x-auto rounded-lg border border-line bg-bg px-3 py-2 font-mono text-xs text-accent">
            $ {c.cmd}
          </code>
        )}
        <button
          onClick={onRetry}
          disabled={retrying}
          className="flex items-center gap-2 rounded-lg border border-accent/30 bg-accent/10 px-3.5 py-2 text-sm text-accent transition hover:bg-accent/20 disabled:opacity-60"
        >
          {retrying ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
          {retrying ? "Retrying…" : "Retry scan"}
        </button>
      </div>
    </div>
  );
}
