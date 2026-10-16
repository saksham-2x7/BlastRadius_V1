import "server-only";
import type { AdvisorProvider } from "./provider";
import { mockProvider } from "./mock";
import { claudeProvider } from "./claude";
import { geminiProvider } from "./gemini";

/**
 * ADVISOR_PROVIDER: "gemini" | "claude" | "mock" | "auto" (default).
 * "auto" picks Gemini if GEMINI_API_KEY is set, else Claude if ANTHROPIC_API_KEY is set, else the keyword mock (no LLM).
 * Unknown values return null.
 */
export function getProvider(): AdvisorProvider | null {
  const name = (process.env.ADVISOR_PROVIDER ?? "auto").toLowerCase();
  if (name === "mock") return mockProvider;
  if (name === "gemini") return geminiProvider;
  if (name === "claude") return claudeProvider;
  if (name === "auto") {
    if (process.env.GEMINI_API_KEY) return geminiProvider;
    if (process.env.ANTHROPIC_API_KEY) return claudeProvider;
    return mockProvider;
  }
  return null;
}

export { mcpToolSource } from "./mcp";
