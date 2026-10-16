import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createMockToken, verifyMockToken } from "@/lib/mock-checkout";

beforeEach(() => {
  vi.stubEnv("NEXTAUTH_SECRET", "test-secret");
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.useRealTimers();
});

describe("mock checkout token", () => {
  it("round-trips for the user it was issued to", () => {
    expect(verifyMockToken(createMockToken("user-1"))).toEqual({ uid: "user-1", plan: "pro" });
  });

  it("rejects a tampered payload or signature", () => {
    const [payload, sig] = createMockToken("user-1").split(".");
    const forged = Buffer.from(JSON.stringify({ uid: "user-2", plan: "pro", exp: Date.now() + 1e6 })).toString("base64url");
    expect(verifyMockToken(`${forged}.${sig}`)).toBeNull();
    expect(verifyMockToken(`${payload}.${sig.slice(0, -2)}xx`)).toBeNull();
  });

  it("rejects malformed tokens", () => {
    for (const t of ["", "abc", "a.b", "."]) expect(verifyMockToken(t)).toBeNull();
  });

  it("expires after 30 minutes", () => {
    vi.useFakeTimers();
    const token = createMockToken("user-1");
    vi.advanceTimersByTime(29 * 60 * 1000);
    expect(verifyMockToken(token)).not.toBeNull();
    vi.advanceTimersByTime(2 * 60 * 1000);
    expect(verifyMockToken(token)).toBeNull();
  });

  it("is not valid under a different secret", () => {
    const token = createMockToken("user-1");
    vi.stubEnv("NEXTAUTH_SECRET", "another-secret");
    expect(verifyMockToken(token)).toBeNull();
  });

  it("refuses to sign without a secret", () => {
    vi.stubEnv("NEXTAUTH_SECRET", "");
    expect(() => createMockToken("user-1")).toThrow(/NEXTAUTH_SECRET/);
  });
});
