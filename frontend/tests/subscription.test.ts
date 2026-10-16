import { beforeEach, describe, expect, it, vi } from "vitest";

const engineFetch = vi.fn();
vi.mock("@/lib/engine", () => ({ engineFetch: (...a: unknown[]) => engineFetch(...a) }));

import { findUserByCustomer, getAccount, getPlanOrFree, setAccount } from "@/lib/subscription";

beforeEach(() => {
  engineFetch.mockReset();
});

describe("subscription", () => {
  it("URL-encodes the user id", async () => {
    engineFetch.mockResolvedValue({ user_id: "a/b", plan: "pro" });
    await getAccount("a/b c");
    expect(engineFetch).toHaveBeenCalledWith("/api/account/a%2Fb%20c");
  });

  it("coerces an unknown stored plan to free", async () => {
    engineFetch.mockResolvedValue({ user_id: "u", plan: "platinum" });
    expect((await getAccount("u")).plan).toBe("free");
  });

  it("getPlanOrFree falls back to free when the engine is down", async () => {
    engineFetch.mockRejectedValue(new Error("down"));
    expect(await getPlanOrFree("u")).toBe("free");
  });

  it("setAccount posts snake_case fields with nulls for the missing ones", async () => {
    engineFetch.mockResolvedValue({});
    await setAccount({ userId: "u", plan: "pro" });
    const [path, init] = engineFetch.mock.calls[0];
    expect(path).toBe("/api/account");
    expect(JSON.parse(init.body)).toEqual({ user_id: "u", plan: "pro", email: null, customer_id: null });
  });

  it("findUserByCustomer returns the mapped user", async () => {
    engineFetch.mockResolvedValue({ user_id: "u9" });
    expect(await findUserByCustomer("cus_1")).toBe("u9");
  });
});
