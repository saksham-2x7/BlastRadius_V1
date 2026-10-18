import { getProvider, mcpToolSource } from "@/lib/advisor";
import { CHAT_LIMITS, type AdvisorEvent, type ChatMessage } from "@/lib/advisor/types";
import { currentUser, fail, unauthorized } from "@/lib/session";
import { workspaceHeaders } from "@/lib/workspace";
import type { CutResult, ExplainResult } from "@/lib/advisor/results";
import type { ToolSource } from "@/lib/advisor/tools";

// Streaming answers (tool calls + LLM) can take 10-30 s; allow up to 60 s on Vercel.
export const maxDuration = 60;

// Tiny in-memory limiter (per server instance): protects a future paid LLM backend from a runaway client.
const WINDOW_MS = 60_000;
const MAX_PER_WINDOW = 15;
const hits = new Map<string, number[]>();
function limited(userId: string): boolean {
  const now = Date.now();
  const recent = (hits.get(userId) ?? []).filter((t) => now - t < WINDOW_MS);
  recent.push(now);
  hits.set(userId, recent);
  return recent.length > MAX_PER_WINDOW;
}

function parseMessages(body: unknown): ChatMessage[] | null {
  const raw = (body as { messages?: unknown } | null)?.messages;
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > CHAT_LIMITS.maxMessages) return null;
  const out: ChatMessage[] = [];
  for (const m of raw) {
    const { role, content } = (m ?? {}) as Partial<ChatMessage>;
    if ((role !== "user" && role !== "assistant") || typeof content !== "string") return null;
    if (content.length === 0 || content.length > CHAT_LIMITS.maxChars) return null;
    out.push({ role, content });
  }
  return out[out.length - 1].role === "user" ? out : null;
}

/**
 * POST /api/chat  { messages: [{ role, content }] }
 * Streams newline-delimited JSON events (see lib/advisor/types.ts). The provider (Claude, or the keyword mock when no
 * ANTHROPIC_API_KEY is set) calls the read-only graph tools through our MCP server. Requires a signed-in session.
 */
export async function POST(req: Request) {
  const user = await currentUser();
  if (!user) return unauthorized();
  if (limited(user.id)) return fail(429, "rate_limited", "Slow down: too many advisor requests. Try again in a minute.");

  const messages = parseMessages(await req.json().catch(() => null));
  if (!messages) {
    return fail(400, "bad_request", `Send 1-${CHAT_LIMITS.maxMessages} messages (max ${CHAT_LIMITS.maxChars} characters each), ending with a user message.`);
  }
  const provider = getProvider();
  if (!provider) {
    return fail(501, "provider_not_configured", `ADVISOR_PROVIDER="${process.env.ADVISOR_PROVIDER}" is not implemented. Use "mock" or add a provider in lib/advisor/.`);
  }

  const enc = new TextEncoder();
  const rawTools = mcpToolSource((await workspaceHeaders(user.id)) ? user.id : undefined);
  // Remember the structured result of explain_attack_path so the UI can draw the cited route on the graph.
  let lastRoutes: string[][] | undefined;
  let lastCut: [string, string][] | undefined;
  const tools: ToolSource = {
    list: () => rawTools.list(),
    call: async (name, args) => {
      const result = await rawTools.call(name, args);
      if (name === "explain_attack_path") lastRoutes = (result as ExplainResult).routes.map((r) => r.route);
      if (name === "suggest_network_cut") lastCut = (result as CutResult).cut.map((e) => [e.source, e.target]);
      return result;
    },
    close: () => rawTools.close(),
  };
  const abort = new AbortController();
  req.signal.addEventListener("abort", () => abort.abort(), { once: true });

  let closed = false; // set when the client disconnects, so we never write to a closed stream
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const send = (e: AdvisorEvent) => {
        if (closed) return;
        try {
          controller.enqueue(enc.encode(JSON.stringify(e) + "\n"));
        } catch {
          closed = true;
        }
      };
      try {
        for await (const event of provider.stream(messages, tools, abort.signal)) {
          if (event.type === "tool_result" && event.ok && event.name === "explain_attack_path" && lastRoutes) send({ ...event, routes: lastRoutes });
          else if (event.type === "tool_result" && event.ok && event.name === "suggest_network_cut" && lastCut) send({ ...event, cut: lastCut });
          else send(event);
        }
        send({ type: "done" });
      } catch (err) {
        console.error("[chat]", err);
        send({ type: "error", message: err instanceof Error && err.message.startsWith("Could not reach the MCP") ? err.message : "The advisor hit an unexpected error. Please try again." });
      } finally {
        await tools.close();
        if (!closed) {
          closed = true;
          try {
            controller.close();
          } catch {
            /* already closed */
          }
        }
      }
    },
    cancel() {
      closed = true;
      abort.abort();
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "application/x-ndjson; charset=utf-8",
      "Cache-Control": "no-store, no-transform",
      "X-Accel-Buffering": "no",
      "X-Advisor-Provider": provider.name,
    },
  });
}
