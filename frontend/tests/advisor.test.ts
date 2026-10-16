import { afterEach, describe, expect, it, vi } from "vitest";
import { summarize, toolErrorMessage, type ToolSource } from "@/lib/advisor/tools";
import { getProvider } from "@/lib/advisor";
import { mockProvider } from "@/lib/advisor/mock";
import { EngineError } from "@/lib/engine";
import type { AdvisorEvent } from "@/lib/advisor/types";

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("summarize", () => {
  it("describes a simulation", () => {
    expect(summarize("simulate_fix", { finding_id: "F1", paths_before: 4, paths_after: 2, paths_eliminated: 2 })).toBe("F1: 4 → 2 paths (−2) · read-only");
  });
  it("pluralises choke points", () => {
    const base = { total_attack_paths: 4, top_findings: [] };
    expect(summarize("get_attack_paths", { ...base, choke_points: [{}] })).toContain("1 choke point ·");
    expect(summarize("get_attack_paths", { ...base, choke_points: [{}, {}] })).toContain("2 choke points ·");
  });
  it("tells applied fixes from refusals", () => {
    const r = { finding_id: "F3", paths_before: 4, paths_after: 3 };
    expect(summarize("apply_safe_fix", { ...r, decision: "applied" })).toContain("applied");
    expect(summarize("apply_safe_fix", { ...r, decision: "needs_human_approval" })).toContain("needs human approval");
  });
  it("falls back for unknown tools", () => expect(summarize("nope", {})).toBe("done"));
});

describe("toolErrorMessage", () => {
  it("prefers the engine's message", () => {
    expect(toolErrorMessage(new EngineError({ kind: "unknown", status: 500, message: "engine says no" }))).toBe("engine says no");
    expect(toolErrorMessage(new Error("boom"))).toBe("boom");
    expect(toolErrorMessage("weird")).toBe("Tool call failed.");
  });
});

describe("getProvider", () => {
  it("honours an explicit choice and rejects unknown ones", () => {
    vi.stubEnv("ADVISOR_PROVIDER", "mock");
    expect(getProvider()?.name).toBe("mock");
    vi.stubEnv("ADVISOR_PROVIDER", "skynet");
    expect(getProvider()).toBeNull();
  });
  it("auto falls back to the keyword mock without any API key", () => {
    vi.stubEnv("ADVISOR_PROVIDER", "auto");
    vi.stubEnv("GEMINI_API_KEY", "");
    vi.stubEnv("ANTHROPIC_API_KEY", "");
    expect(getProvider()?.name).toBe("mock");
  });
  it("auto prefers Gemini, then Claude", () => {
    vi.stubEnv("ADVISOR_PROVIDER", "auto");
    vi.stubEnv("GEMINI_API_KEY", "g");
    vi.stubEnv("ANTHROPIC_API_KEY", "a");
    expect(getProvider()?.name).toBe("gemini");
    vi.stubEnv("GEMINI_API_KEY", "");
    expect(getProvider()?.name).toBe("claude");
  });
});

describe("mock provider", () => {
  it("calls the tool, reports its result and answers from it", async () => {
    const calls: string[] = [];
    const tools: ToolSource = {
      list: async () => [],
      close: async () => {},
      call: async (name) => {
        calls.push(name);
        return { ranking: [{ host: "api-gateway", betweenness: 3.25, pagerank: 0.2, attack_paths: 3, software: null }], method: "m", note: "n" };
      },
    };
    const events: AdvisorEvent[] = [];
    for await (const e of mockProvider.stream([{ role: "user", content: "which hosts are choke points?" }], tools, new AbortController().signal)) events.push(e);
    expect(calls).toEqual(["get_choke_points"]);
    expect(events.find((e) => e.type === "tool_result")).toMatchObject({ ok: true, name: "get_choke_points" });
    expect(events.filter((e) => e.type === "text").map((e) => (e as { delta: string }).delta).join("")).toContain("api-gateway");
  });

  it("surfaces a failing tool without crashing", async () => {
    const tools: ToolSource = { list: async () => [], close: async () => {}, call: async () => { throw new Error("db down"); } };
    const events: AdvisorEvent[] = [];
    for await (const e of mockProvider.stream([{ role: "user", content: "which hosts are choke points?" }], tools, new AbortController().signal)) events.push(e);
    expect(events.find((e) => e.type === "tool_result")).toMatchObject({ ok: false, summary: "db down" });
  });
});
