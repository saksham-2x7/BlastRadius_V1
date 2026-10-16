import "server-only";
import { ApiError, FunctionCallingConfigMode, GoogleGenAI, type Content, type FunctionCall, type Part } from "@google/genai";
import type { AdvisorProvider } from "./provider";
import type { AdvisorEvent } from "./types";
import { summarize, toolErrorMessage } from "./tools";
import { SYSTEM } from "./system";

/**
 * Gemini advisor (works on Google's free tier). Streams Gemini's answer and runs its function calls against our MCP server.
 * Config: GEMINI_API_KEY (required), GEMINI_MODEL (preferred model), GEMINI_BASE_URL (testing only).
 */
// Tried in order: if a model is overloaded or unavailable (new models often are), the next one is used automatically.
const MODELS = [...new Set([process.env.GEMINI_MODEL || "gemini-3.6-flash", "gemini-3.5-flash-lite", "gemini-2.5-flash"])];
const MAX_TURNS = 6; // function-calling round trips per question
const MAX_TOOL_CHARS = 24_000; // cap on how much of one tool result is sent to the model

/** Gemini accepts only a subset of JSON Schema, so keep just the keywords it understands. */
const ALLOWED = new Set(["type", "description", "properties", "required", "items", "enum", "minimum", "maximum", "minLength", "maxLength", "pattern"]);
function sanitizeSchema(node: unknown): unknown {
  if (Array.isArray(node)) return node.map(sanitizeSchema);
  if (node && typeof node === "object") {
    return Object.fromEntries(
      Object.entries(node as Record<string, unknown>)
        .filter(([k]) => ALLOWED.has(k))
        .map(([k, v]) => [k, k === "properties" ? mapValues(v as Record<string, unknown>, sanitizeSchema) : sanitizeSchema(v)]),
    );
  }
  return node;
}
const mapValues = (o: Record<string, unknown>, f: (v: unknown) => unknown) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, f(v)]));

export const geminiProvider: AdvisorProvider = {
  name: "gemini",

  async *stream(messages, tools, signal): AsyncGenerator<AdvisorEvent> {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      yield { type: "error", message: "GEMINI_API_KEY is not set on the server, so the Gemini advisor is unavailable." };
      return;
    }
    const ai = new GoogleGenAI({
      apiKey,
      ...(process.env.GEMINI_BASE_URL ? { httpOptions: { baseUrl: process.env.GEMINI_BASE_URL } } : {}),
    });

    const specs = await tools.list();
    const functionDeclarations = specs.map((s) => ({
      name: s.name,
      description: s.description,
      parametersJsonSchema: sanitizeSchema(s.input_schema),
    }));
    const known = new Set(specs.map((s) => s.name));
    const contents: Content[] = messages.map((m) => ({ role: m.role === "assistant" ? "model" : "user", parts: [{ text: m.content }] }));

    let modelIdx = 0; // sticks to the first model that works for the rest of this question
    let malformed = 0; // Gemini occasionally emits an invalid tool call; we retry instead of failing
    let textOnly = false; // after such a failure with tool results in hand, force a plain-text answer
    for (let turn = 0; turn < MAX_TURNS && !signal.aborted; turn++) {
      const modelParts: Part[] = [];
      const calls: FunctionCall[] = [];
      let finishReason: string | undefined;

      try {
        const stream = await ai.models.generateContentStream({
          model: MODELS[modelIdx],
          contents,
          config: {
            systemInstruction: SYSTEM,
            tools: [{ functionDeclarations }],
            ...(textOnly ? { toolConfig: { functionCallingConfig: { mode: FunctionCallingConfigMode.NONE } } } : {}),
            abortSignal: signal,
          },
        });
        for await (const chunk of stream) {
          const candidate = chunk.candidates?.[0];
          finishReason = candidate?.finishReason ?? finishReason;
          for (const part of candidate?.content?.parts ?? []) {
            modelParts.push(part); // echoed back unchanged (keeps Gemini's thought signatures valid)
            if (part.functionCall) calls.push(part.functionCall);
            else if (part.text && !part.thought) yield { type: "text", delta: part.text };
          }
        }
      } catch (err) {
        if (signal.aborted) return;
        // Nothing was streamed yet and another model is available: retry this turn on the next model.
        if (modelParts.length === 0 && modelIdx < MODELS.length - 1 && isRetryable(err)) {
          modelIdx++;
          turn--;
          continue;
        }
        yield { type: "error", message: friendlyError(err) };
        return;
      }

      if (calls.length === 0) {
        if (finishReason === "MAX_TOKENS") yield { type: "text", delta: "\n\n(The answer was cut off. Ask me to continue.)" };
        else if (finishReason && ["SAFETY", "PROHIBITED_CONTENT", "BLOCKLIST", "SPII", "RECITATION"].includes(finishReason)) {
          yield { type: "text", delta: "I can't help with that request." };
        } else if (finishReason === "MALFORMED_FUNCTION_CALL") {
          if (malformed < 2) {
            malformed++;
            if (turn > 0) textOnly = true; // we already have tool results: make it answer from them
            turn--;
            continue;
          }
          yield { type: "error", message: "Gemini produced an invalid tool call. Please try asking again." };
        } else if (modelParts.length === 0) {
          yield { type: "error", message: "Gemini returned an empty answer. Please try again." };
        }
        return;
      }

      // Run every requested tool (in parallel), then return all results in ONE user message.
      contents.push({ role: "model", parts: modelParts });
      const ids = calls.map((c, i) => c.id ?? `call_${turn}_${i}`);
      for (let i = 0; i < calls.length; i++) {
        yield { type: "tool_call", id: ids[i], name: calls[i].name ?? "", args: (calls[i].args ?? {}) as Record<string, unknown> };
      }
      const results = await Promise.all(
        calls.map(async (c) => {
          const name = c.name ?? "";
          if (!known.has(name)) return { ok: false as const, name, content: `Unknown tool "${name}".` };
          try {
            const r = await tools.call(name, (c.args ?? {}) as Record<string, unknown>);
            return { ok: true as const, name, result: r, content: JSON.stringify(r).slice(0, MAX_TOOL_CHARS) };
          } catch (err) {
            return { ok: false as const, name, content: toolErrorMessage(err) };
          }
        }),
      );
      const responseParts: Part[] = [];
      for (let i = 0; i < results.length; i++) {
        const r = results[i];
        yield { type: "tool_result", id: ids[i], name: r.name, ok: r.ok, summary: r.ok ? summarize(r.name, r.result) : r.content };
        responseParts.push({
          functionResponse: {
            ...(calls[i].id ? { id: calls[i].id } : {}),
            name: r.name,
            // Tool output is passed as a JSON-encoded string so it is treated as data, whatever it contains.
            response: r.ok ? { output: r.content } : { error: r.content },
          },
        });
      }
      contents.push({ role: "user", parts: responseParts });
    }
    if (!signal.aborted) yield { type: "text", delta: "\n\n(Stopped after too many tool steps. Try a more specific question.)" };
  },
};

/** Overloaded (503), internal (500), rate-limited (429) or unknown model (404): worth trying the next model. */
const isRetryable = (err: unknown) => err instanceof ApiError && [404, 429, 500, 503].includes(err.status);

/** Maps SDK errors to messages that are useful to the user and never leak keys or internals. */
function friendlyError(err: unknown): string {
  if (err instanceof ApiError) {
    const msg = err.message ?? "";
    if (err.status === 429) return "Gemini's free-tier limit was reached. Wait a minute and try again, (the advisor already tried its backup models).";
    if (err.status === 401 || err.status === 403 || (err.status === 400 && /api key/i.test(msg))) {
      // Google's reason (e.g. "API key not valid", "IP address restriction") helps diagnose a bad deploy config. Never echo a key.
      const reason = msg.replace(/AIza[\w-]+|AQ\.[\w.-]+/g, "[key]").replace(/\s+/g, " ").slice(0, 160);
      console.error("[advisor/gemini] key rejected:", err.status, reason);
      return `Gemini rejected the API key (HTTP ${err.status}: ${reason}). Check GEMINI_API_KEY on the server.`;
    }
    if (err.status === 404) return "That Gemini model was not found. Set GEMINI_MODEL to one listed at aistudio.google.com, e.g. gemini-3.6-flash.";
    if (err.status === 503 || err.status === 500) return "Gemini is overloaded right now (the advisor tried its backup models too). Try again in a moment.";
    if (err.status === 400) return `Gemini rejected the request: ${msg.slice(0, 200)}`;
    return `Gemini API error (${err.status}). Please try again.`;
  }
  console.error("[advisor/gemini]", err);
  return "The advisor could not reach Gemini. Check your network and try again.";
}
