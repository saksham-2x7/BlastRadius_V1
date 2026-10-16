import { describe, expect, it } from "vitest";
import { PLANS, isPlan } from "@/lib/plans";
import { fmtEpssText } from "@/lib/advisor/format";

describe("plans", () => {
  it("only recognises the two plan ids", () => {
    expect(isPlan("free")).toBe(true);
    expect(isPlan("pro")).toBe(true);
    for (const bad of ["enterprise", "", null, undefined, 3]) expect(isPlan(bad)).toBe(false);
  });

  it("keys each plan by its own id", () => {
    for (const [key, plan] of Object.entries(PLANS)) expect(plan.id).toBe(key);
  });

  it("gates auto-fix to Pro", () => {
    const auto = (p: "free" | "pro") => PLANS[p].features.find((f) => /auto-fix/i.test(f.text))?.included;
    expect(auto("free")).toBe(false);
    expect(auto("pro")).toBe(true);
  });
});

describe("fmtEpssText", () => {
  it("rounds to a percent and floors tiny values", () => {
    expect(fmtEpssText(0.004)).toBe("<1%");
    expect(fmtEpssText(0.5)).toBe("50%");
    expect(fmtEpssText(0.99999)).toBe("100%");
  });
});
