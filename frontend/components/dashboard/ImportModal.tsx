"use client";

import { useRef, useState } from "react";
import { motion } from "framer-motion";
import { Loader2, Upload, X } from "lucide-react";
import { IMPORT_EXAMPLE, IMPORT_TERRAFORM_EXAMPLE } from "@/lib/import-example";

/** Paste or upload your own inventory (JSON, optionally with Trivy reports). Returns an error message, or null on success. */
export default function ImportModal({ onClose, onImport }: { onClose: () => void; onImport: (payload: unknown) => Promise<string | null> }) {
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const submit = async () => {
    setError(null);
    let payload: unknown;
    try {
      payload = JSON.parse(text);
    } catch {
      return setError("That is not valid JSON. Click “Load example” to see the format.");
    }
    setBusy(true);
    const err = await onImport(payload);
    setBusy(false);
    if (err) setError(err);
  };

  const readFile = (f: File | undefined) => {
    if (!f) return;
    if (f.size > 2_000_000) return setError("That file is too large (2 MB max).");
    f.text().then(setText, () => setError("Could not read that file."));
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-[60] grid place-items-center bg-black/40 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="import-title"
      onClick={onClose}
      onKeyDown={(e) => e.key === "Escape" && onClose()}
    >
      <div className="flex max-h-[90vh] w-full max-w-2xl flex-col rounded-2xl border border-line bg-bg p-6 shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 id="import-title" className="text-lg font-medium">Use your own data</h2>
            <p className="mt-1 text-sm text-muted">
              Paste or upload your inventory as JSON (or the output of <code className="font-mono text-xs">terraform show -json</code> under <code className="font-mono text-xs">terraform</code>): hosts, data stores, who can reach whom, and findings (or Trivy / Grype reports under <code className="font-mono text-xs">trivy</code> / <code className="font-mono text-xs">grype</code>). It becomes
              your own private FalkorDB graph; the shared sample is untouched. KEV and EPSS are fetched live.
            </p>
          </div>
          <button onClick={onClose} aria-label="Close" className="grid h-9 w-9 shrink-0 place-items-center rounded-lg text-muted hover:bg-panel hover:text-fg">
            <X className="h-4 w-4" />
          </button>
        </div>
        <textarea
          autoFocus
          value={text}
          onChange={(e) => setText(e.target.value)}
          spellCheck={false}
          placeholder='{ "hosts": [...], "datastores": [...], "edges": [...], "findings": [...] }'
          className="mt-4 h-64 w-full resize-none rounded-xl border border-line bg-panel p-3 font-mono text-xs"
        />
        {error && (
          <p role="alert" className="mt-2 text-sm text-danger">
            {error}
          </p>
        )}
        <p className="mt-2 text-xs text-muted">Only public, synthetic or your own data. Never paste credentials or private customer data. 2 MB max.</p>
        <div className="mt-4 flex flex-wrap items-center justify-between gap-2">
          <div className="flex gap-2">
            <button onClick={() => setText(JSON.stringify(IMPORT_EXAMPLE, null, 2))} className="h-10 rounded-full border border-line px-4 text-sm text-muted transition hover:text-fg">
              Load example
            </button>
            <button onClick={() => setText(JSON.stringify(IMPORT_TERRAFORM_EXAMPLE, null, 2))} className="h-10 rounded-full border border-line px-4 text-sm text-muted transition hover:text-fg">
              Load Terraform example
            </button>
            <button onClick={() => fileRef.current?.click()} className="flex h-10 items-center gap-1.5 rounded-full border border-line px-4 text-sm text-muted transition hover:text-fg">
              <Upload className="h-3.5 w-3.5" /> Upload .json
            </button>
            <input ref={fileRef} type="file" accept="application/json,.json" className="hidden" onChange={(e) => readFile(e.target.files?.[0])} />
          </div>
          <button onClick={submit} disabled={busy || !text.trim()} className="btn-chrome flex h-10 items-center gap-2 rounded-full px-5 text-sm font-semibold disabled:opacity-50">
            {busy && <Loader2 className="h-4 w-4 animate-spin" />} {busy ? "Importing…" : "Import and scan"}
          </button>
        </div>
      </div>
    </motion.div>
  );
}
