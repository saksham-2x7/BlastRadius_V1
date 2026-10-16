import "server-only";
import type { AdvisorEvent, ChatMessage } from "./types";
import type { ToolSource } from "./tools";

/**
 * The seam where an LLM plugs in. A provider receives the conversation and a ToolSource (our MCP server) and yields events:
 *   - `tool_call` / `tool_result` while it uses tools, `text` deltas for the answer, errors as `error`.
 * Implementations: mockProvider (keyword rules, no LLM) and claudeProvider (Claude via the Anthropic SDK + MCP tools).
 * The tools are read-only by design, so the model can look but never change anything.
 */
export interface AdvisorProvider {
  readonly name: string;
  stream(messages: ChatMessage[], tools: ToolSource, signal: AbortSignal): AsyncGenerator<AdvisorEvent>;
}
