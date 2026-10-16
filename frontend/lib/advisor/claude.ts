import "server-only";
import Anthropic from "@anthropic-ai/sdk";
import type { AdvisorProvider } from "./provider";
import type { AdvisorEvent } from "./types";
import { summarize, toolErrorMessage } from "./tools";
import { SYSTEM } from "./system";

/**
 * Claude advisor: streams Claude's answer and runs its tool calls against our MCP server (read-only tools).
 * Config (all optional): ANTHROPIC_API_KEY (required), ANTHROPIC_MODEL, ADVISOR_EFFORT, ADVISOR_REFUSAL_FALLBACK=off.
 */
const MODEL = process.env.ANTHROPIC_MODEL || "claude-opus-5-5";
const EFFORT = (["low", "medium", "high", "xhigh", "max"] as const).find((e) => e === process.env.ADVISOR_EFFORT) ?? "medium";
const MAX_TURNS = 6; // tool-use round trips per question
const MAX_TOOL_CHARS = 24_000; // cap on how much of one tool result is sent to the model

export const claudeProvider: AdvisorProvider = {
  name: "claude",

  async *stream(messages, tools, signal): AsyncGenerator<AdvisorEvent> {
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
      yield { type: "error", message: "ANTHROPIC_API_KEY is not set on the server, so the Claude advisor is unavailable." };
      return;
    }
    // The SDK also honours ANTHROPIC_BASE_URL, which is how this loop is tested against a local fake API.
    const client = new Anthropic({ apiKey, maxRetries: 2 });

    const specs = await tools.list();
    const toolDefs: Anthropic.Beta.BetaTool[] = specs.map((s) => ({
      name: s.name,
      description: s.description,
      input_schema: s.input_schema as Anthropic.Beta.BetaTool["input_schema"],
    }));
    const convo: Anthropic.Beta.BetaMessageParam[] = messages.map((m) => ({ role: m.role, content: m.content }));

    // Server-side refusal fallback (recommended for this model). If the API rejects the parameter we retry once without it.
    let fallbacks = process.env.ADVISOR_REFUSAL_FALLBACK !== "off";
    let turns = 0;

    while (turns < MAX_TURNS && !signal.aborted) {
      let final: Anthropic.Beta.BetaMessage;
      try {
        const stream = client.beta.messages.stream(
          {
            model: MODEL,
            max_tokens: 16_000,
            system: SYSTEM,
            tools: toolDefs,
            messages: convo,
            output_config: { effort: EFFORT },
            ...(fallbacks ? { betas: ["server-side-fallback-2026-07-01" as const], fallbacks: "default" as const } : {}),
          },
          { signal },
        );
        for await (const event of stream) {
          if (event.type === "content_block_delta" && event.delta.type === "text_delta") {
            yield { type: "text", delta: event.delta.text };
          }
        }
        final = await stream.finalMessage();
      } catch (err) {
        if (signal.aborted) return;
        if (fallbacks && err instanceof Anthropic.BadRequestError && /fallback/i.test(err.message)) {
          fallbacks = false; // not available for this key/model: carry on without it
          continue;
        }
        yield { type: "error", message: friendlyError(err) };
        return;
      }
      turns++;

      if (final.stop_reason === "refusal") {
        yield { type: "text", delta: "I can't help with that request." };
        return;
      }
      if (final.stop_reason === "max_tokens") {
        yield { type: "text", delta: "\n\n(The answer was cut off. Ask me to continue.)" };
        return;
      }
      if (final.stop_reason !== "tool_use") return; // end_turn: the answer has been streamed

      // Run every requested tool (in parallel), then return all results in ONE user message.
      convo.push({ role: "assistant", content: final.content });
      const calls = final.content.filter((b): b is Anthropic.Beta.BetaToolUseBlock => b.type === "tool_use");
      for (const c of calls) yield { type: "tool_call", id: c.id, name: c.name, args: (c.input ?? {}) as Record<string, unknown> };

      const known = new Set(specs.map((s) => s.name));
      const results = await Promise.all(
        calls.map(async (c) => {
          if (!known.has(c.name)) return { c, ok: false as const, content: `Unknown tool "${c.name}".` };
          try {
            const r = await tools.call(c.name, (c.input ?? {}) as Record<string, unknown>);
            return { c, ok: true as const, result: r, content: JSON.stringify(r).slice(0, MAX_TOOL_CHARS) };
          } catch (err) {
            return { c, ok: false as const, content: toolErrorMessage(err) };
          }
        }),
      );
      for (const r of results) {
        yield { type: "tool_result", id: r.c.id, name: r.c.name, ok: r.ok, summary: r.ok ? summarize(r.c.name, r.result) : r.content };
      }
      convo.push({
        role: "user",
        content: results.map((r) => ({ type: "tool_result" as const, tool_use_id: r.c.id, content: r.content, ...(r.ok ? {} : { is_error: true }) })),
      });
    }
    if (!signal.aborted) yield { type: "text", delta: "\n\n(Stopped after too many tool steps. Try a more specific question.)" };
  },
};

/** Maps SDK errors to messages that are useful to the user and never leak keys or internals. */
function friendlyError(err: unknown): string {
  if (err instanceof Anthropic.AuthenticationError) return "The Anthropic API key was rejected. Check ANTHROPIC_API_KEY.";
  if (err instanceof Anthropic.PermissionDeniedError) return "This API key is not allowed to use that model. Set ANTHROPIC_MODEL to one you can use.";
  if (err instanceof Anthropic.NotFoundError) return "The configured Claude model was not found. Check ANTHROPIC_MODEL.";
  if (err instanceof Anthropic.RateLimitError) return "Claude is rate-limiting this key right now. Try again in a minute.";
  if (err instanceof Anthropic.BadRequestError) return `Claude rejected the request: ${err.message.slice(0, 200)}`;
  if (err instanceof Anthropic.APIConnectionError) return "Could not reach the Anthropic API. Check your network and try again.";
  if (err instanceof Anthropic.APIError) return `Claude API error (${err.status ?? "unknown"}). Please try again.`;
  console.error("[advisor/claude]", err);
  return "The advisor hit an unexpected error. Please try again.";
}
