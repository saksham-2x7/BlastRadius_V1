import { afterEach, describe, expect, it, vi } from "vitest";
import { EngineError, engineFetch, toErrorInfo } from "@/lib/engine";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

const respond = (status: number, body: unknown) => new Response(typeof body === "string" ? body : JSON.stringify(body), { status });

describe("toErrorInfo", () => {
  it("maps engine_unavailable with host and port", () => {
    expect(toErrorInfo(503, { error: "engine_unavailable", message: "down", host: "db", port: 6379 })).toMatchObject({
      kind: "engine_unavailable", host: "db", port: 6379,
    });
  });
  it("tells a bad engine key apart from an expired session", () => {
    expect(toErrorInfo(401, { detail: "Invalid or missing engine key" }).message).toMatch(/ENGINE_API_KEY/);
    expect(toErrorInfo(401, {}).kind).toBe("unauthorized");
  });
  it("turns a 422 validation error into a readable message", () => {
    const info = toErrorInfo(422, { detail: [{ loc: ["body", "edges", 0], msg: "Value error, Edge [a, b] mentions an unknown node." }] });
    expect(info).toMatchObject({ kind: "rejected" });
    expect(info.message).toBe("Invalid input at edges.0: Edge [a, b] mentions an unknown node.");
  });
  it("handles upgrade_required, fix_rejected and unknown bodies", () => {
    expect(toErrorInfo(402, { error: "upgrade_required" }).kind).toBe("upgrade_required");
    expect(toErrorInfo(409, { error: "fix_rejected", message: "no" })).toMatchObject({ kind: "rejected", message: "no" });
    expect(toErrorInfo(500, null)).toMatchObject({ kind: "unknown", message: "Engine returned HTTP 500." });
  });
});

describe("engineFetch", () => {
  it("sends the engine key and parses JSON", async () => {
    vi.stubEnv("ENGINE_API_KEY", "k123");
    const fetchMock = vi.fn().mockResolvedValue(respond(200, { ok: true }));
    vi.stubGlobal("fetch", fetchMock);
    await expect(engineFetch("/api/scan")).resolves.toEqual({ ok: true });
    expect(fetchMock.mock.calls[0][1].headers["X-Engine-Key"]).toBe("k123");
  });

  it("throws an EngineError carrying the parsed info on HTTP errors", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(respond(422, { detail: [{ loc: ["body", "x"], msg: "bad" }] })));
    await expect(engineFetch("/api/import")).rejects.toMatchObject({ info: { kind: "rejected", status: 422 } });
  });

  it("reports an unreachable API instead of leaking the network error", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("fetch failed")));
    const err = (await engineFetch("/api/scan").catch((e) => e)) as EngineError;
    expect(err).toBeInstanceOf(EngineError);
    expect(err.info.kind).toBe("api_unreachable");
  });

  it("tolerates non-JSON error bodies", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(respond(502, "<html>Bad gateway</html>")));
    await expect(engineFetch("/x")).rejects.toMatchObject({ info: { status: 502, kind: "unknown" } });
  });
});
