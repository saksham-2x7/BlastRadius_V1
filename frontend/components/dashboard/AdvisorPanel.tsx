"use client";

import { Fragment, useCallback, useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { CornerDownLeft, Loader2, Square, Terminal, Trash2, X } from "lucide-react";
import type { AdvisorEvent, ChatMessage } from "@/lib/advisor/types";

interface Step {
  id: string;
  name: string;
  args: Record<string, unknown>;
  status: "running" | "ok" | "error";
  summary?: string;
}
interface UiMessage {
  id: string;
  role: "user" | "assistant";
  text: string;
  steps: Step[];
  streaming: boolean;
  error?: string;
}

const SUGGESTIONS = [
  "Which vulnerability should I patch first?",
  "Which findings are in CISA KEV?",
  "What if I patch F4?",
  "Give me an attack path overview",
];

let counter = 0;
const uid = () => `m${++counter}-${Date.now()}`;

const fmtArgs = (a: Record<string, unknown>) =>
  Object.entries(a)
    .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
    .join(", ");

/** Minimal, safe formatter: **bold**, `code` and "• " bullets. Everything renders as React text (no HTML injection). */
function Rich({ text }: { text: string }) {
  return (
    <>
      {text.split("\n").map((line, i) => {
        const bullet = /^(•|\*|-) /.test(line); // models write bullets as "* " or "- "
        const body = bullet ? line.slice(2) : line;
        const parts = body.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).filter(Boolean);
        return (
          <div key={i} className={`${bullet ? "flex gap-2 pl-1" : ""} ${line === "" ? "h-2" : ""}`}>
            {bullet && <span className="text-accent">▸</span>}
            <span className="min-w-0 break-words">
              {parts.map((p, j) =>
                p.startsWith("**") ? (
                  <strong key={j} className="font-semibold text-fg">
                    {p.slice(2, -2)}
                  </strong>
                ) : p.startsWith("`") ? (
                  <code key={j} className="rounded bg-accent/10 px-1 text-accent">
                    {p.slice(1, -1)}
                  </code>
                ) : (
                  <Fragment key={j}>{p}</Fragment>
                )
              )}
            </span>
          </div>
        );
      })}
    </>
  );
}

function StepLine({ step }: { step: Step }) {
  return (
    <div className="my-1 rounded-md border border-line bg-black/[0.02] px-2.5 py-1.5">
      <div className="flex items-center gap-2 text-accent">
        {step.status === "running" ? (
          <Loader2 className="h-3 w-3 shrink-0 animate-spin" />
        ) : (
          <span className={step.status === "ok" ? "text-ok" : "text-danger"}>{step.status === "ok" ? "✓" : "✗"}</span>
        )}
        <span className="min-w-0 break-all">
          {step.name}({fmtArgs(step.args)})
        </span>
      </div>
      {step.summary && <div className={`mt-0.5 pl-5 text-[11px] ${step.status === "error" ? "text-danger" : "text-muted"}`}>{step.summary}</div>}
    </div>
  );
}

export default function AdvisorPanel({ open, onClose, suggestions = SUGGESTIONS, onAgentAction, onRoutes }: { open: boolean; onClose: () => void; suggestions?: string[]; onAgentAction?: () => void; onRoutes?: (routes: string[][]) => void }) {
  const [messages, setMessages] = useState<UiMessage[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [provider, setProvider] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (!open) return;
    inputRef.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  useEffect(() => () => abortRef.current?.abort(), []);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages]);

  const patch = useCallback((id: string, fn: (m: UiMessage) => UiMessage) => {
    setMessages((all) => all.map((m) => (m.id === id ? fn(m) : m)));
  }, []);

  const apply = useCallback(
    (id: string, e: AdvisorEvent) => {
      if (e.type === "text") patch(id, (m) => ({ ...m, text: m.text + e.delta }));
      else if (e.type === "tool_call")
        patch(id, (m) => ({ ...m, steps: [...m.steps, { id: e.id, name: e.name, args: e.args, status: "running" }] }));
      else if (e.type === "tool_result") {
        if (e.ok && e.name === "apply_safe_fix") onAgentAction?.();
        if (e.ok && e.routes?.length) onRoutes?.(e.routes);
        patch(id, (m) => ({
          ...m,
          steps: m.steps.map((s) => (s.id === e.id ? { ...s, status: e.ok ? "ok" : "error", summary: e.summary } : s)),
        }));
      } else if (e.type === "error") patch(id, (m) => ({ ...m, error: e.message }));
    },
    [patch, onAgentAction, onRoutes]
  );

  const send = useCallback(
    async (raw: string) => {
      const text = raw.trim();
      if (!text || busy) return;
      const history: ChatMessage[] = [
        ...messages.filter((m) => m.text).map((m) => ({ role: m.role, content: m.text })),
        { role: "user" as const, content: text },
      ];
      const replyId = uid();
      setMessages((all) => [
        ...all,
        { id: uid(), role: "user", text, steps: [], streaming: false },
        { id: replyId, role: "assistant", text: "", steps: [], streaming: true },
      ]);
      setInput("");
      setBusy(true);
      const ctrl = new AbortController();
      abortRef.current = ctrl;

      try {
        const res = await fetch("/api/chat", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ messages: history }),
          signal: ctrl.signal,
        });
        setProvider(res.headers.get("X-Advisor-Provider"));
        if (!res.ok || !res.body) {
          const body = (await res.json().catch(() => null)) as { message?: string } | null;
          patch(replyId, (m) => ({ ...m, error: body?.message ?? `Request failed (${res.status}).` }));
          return;
        }
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buf = "";
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          let nl: number;
          while ((nl = buf.indexOf("\n")) >= 0) {
            const line = buf.slice(0, nl).trim();
            buf = buf.slice(nl + 1);
            if (!line) continue;
            try {
              apply(replyId, JSON.parse(line) as AdvisorEvent);
            } catch {
              /* ignore a malformed line */
            }
          }
        }
      } catch (err) {
        if ((err as Error).name !== "AbortError") patch(replyId, (m) => ({ ...m, error: "Connection lost. Please try again." }));
      } finally {
        patch(replyId, (m) => ({ ...m, streaming: false }));
        setBusy(false);
        abortRef.current = null;
        inputRef.current?.focus();
      }
    },
    [apply, busy, messages, patch]
  );

  const stop = () => abortRef.current?.abort();
  const clear = () => {
    abortRef.current?.abort();
    setMessages([]);
  };

  return (
    <AnimatePresence>
      {open && (
        <motion.aside
          role="dialog"
          aria-label="AI advisor"
          initial={{ x: "100%", opacity: 0.6 }}
          animate={{ x: 0, opacity: 1 }}
          exit={{ x: "100%", opacity: 0.6 }}
          transition={{ type: "spring", stiffness: 380, damping: 38 }}
          className="fixed right-0 top-0 z-[80] flex h-dvh w-full max-w-[460px] flex-col border-l border-line bg-[#f4f2ed]/95 shadow-[-30px_0_80px_-30px_rgba(13,13,15,0.35)] backdrop-blur-xl"
        >
          <div className="hud-scanlines pointer-events-none absolute inset-0" aria-hidden />
          <span className="pointer-events-none absolute left-0 top-0 h-3 w-3 border-l border-t border-accent/60" aria-hidden />
          <span className="pointer-events-none absolute bottom-0 left-0 h-3 w-3 border-b border-l border-accent/60" aria-hidden />

          <header className="relative flex items-center justify-between border-b border-accent/20 px-4 py-3">
            <div className="flex items-center gap-2.5">
              <Terminal className="h-4 w-4 text-accent" />
              <div>
                <div className="font-mono text-xs font-semibold uppercase tracking-[0.18em] text-accent">Advisor // blastradius</div>
                <div className="flex items-center gap-1.5 font-mono text-[10px] text-muted">
                  <span className={`h-1.5 w-1.5 rounded-full ${busy ? "animate-pulse bg-warn" : "bg-ok"}`} />
                  {busy ? "analysing graph…" : "online"} · {provider ? `${provider} provider` : "advisor"} · graph tools over MCP
                </div>
              </div>
            </div>
            <div className="flex items-center gap-1">
              {messages.length > 0 && (
                <button onClick={clear} aria-label="Clear conversation" title="Clear" className="grid h-8 w-8 place-items-center rounded-md text-muted transition hover:bg-black/[0.04] hover:text-fg">
                  <Trash2 className="h-4 w-4" />
                </button>
              )}
              <button onClick={onClose} aria-label="Close advisor" className="grid h-8 w-8 place-items-center rounded-md text-muted transition hover:bg-black/[0.04] hover:text-fg">
                <X className="h-4 w-4" />
              </button>
            </div>
          </header>

          <div ref={scrollRef} className="relative flex-1 space-y-4 overflow-y-auto px-4 py-4 font-mono text-[12.5px] leading-relaxed">
            {messages.length === 0 ? (
              <div>
                <p className="text-muted">
                  <span className="text-accent">$</span> ask about your attack paths. I reason over the live FalkorDB graph and can apply low-risk fixes. High-risk ones always wait for you, and I remember what I did.
                  <span className="cursor-blink text-accent"> _</span>
                </p>
                <div className="mt-4 flex flex-col gap-2">
                  {suggestions.map((s) => (
                    <button
                      key={s}
                      onClick={() => send(s)}
                      className="rounded-lg border border-line bg-black/[0.02] px-3 py-2 text-left text-fg/90 transition hover:border-accent/40 hover:bg-accent/5"
                    >
                      <span className="mr-2 text-accent">❯</span>
                      {s}
                    </button>
                  ))}
                </div>
              </div>
            ) : (
              messages.map((m) =>
                m.role === "user" ? (
                  <div key={m.id} className="flex gap-2 text-fg">
                    <span className="text-accent">❯</span>
                    <span className="min-w-0 break-words">{m.text}</span>
                  </div>
                ) : (
                  <div key={m.id} className="text-fg/90">
                    <div className="mb-1 text-[10px] uppercase tracking-[0.18em] text-accent/70">◆ advisor</div>
                    {m.steps.map((s) => (
                      <StepLine key={s.id} step={s} />
                    ))}
                    {m.text && (
                      <div className="mt-2 text-fg/90">
                        <Rich text={m.text} />
                        {m.streaming && <span className="cursor-blink text-accent">▋</span>}
                      </div>
                    )}
                    {m.streaming && !m.text && m.steps.length === 0 && <span className="cursor-blink text-accent">▋</span>}
                    {m.error && (
                      <p role="alert" className="mt-2 rounded-md border border-danger/30 bg-danger/10 px-2.5 py-1.5 text-danger">
                        {m.error}
                      </p>
                    )}
                  </div>
                )
              )
            )}
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              void send(input);
            }}
            className="relative border-t border-accent/20 p-3"
          >
            <div className="flex items-end gap-2 rounded-xl border border-line bg-bg/80 px-3 py-2 focus-within:border-accent/50">
              <span className="pb-1 font-mono text-accent">❯</span>
              <textarea
                ref={inputRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !e.shiftKey) {
                    e.preventDefault();
                    void send(input);
                  }
                }}
                rows={1}
                maxLength={500}
                placeholder="Ask the advisor…"
                aria-label="Message the advisor"
                className="max-h-28 min-h-[28px] flex-1 resize-none bg-transparent font-mono text-sm text-fg outline-none placeholder:text-muted/60"
              />
              {busy ? (
                <button type="button" onClick={stop} aria-label="Stop" className="grid h-8 w-8 shrink-0 place-items-center rounded-md border border-danger/40 bg-danger/10 text-danger transition hover:bg-danger/20">
                  <Square className="h-3.5 w-3.5 fill-current" />
                </button>
              ) : (
                <button type="submit" disabled={!input.trim()} aria-label="Send" className="grid h-8 w-8 shrink-0 place-items-center rounded-md border border-accent/40 bg-accent/10 text-accent transition hover:bg-accent/20 disabled:opacity-40">
                  <CornerDownLeft className="h-4 w-4" />
                </button>
              )}
            </div>
            <p className="mt-2 font-mono text-[10px] text-muted/70">
              {provider === "mock"
                ? "Mock advisor: answers are templated from real tool results. Set GEMINI_API_KEY on the server to enable Gemini."
                : provider
                  ? `${provider === "gemini" ? "Gemini" : "Claude"} answers from live tool results over MCP. It can apply low-risk fixes; high-risk ones need your approval. Verify before acting.`
                  : "Graph tools over MCP. An LLM is used when an API key is configured on the server."}
            </p>
          </form>
        </motion.aside>
      )}
    </AnimatePresence>
  );
}
