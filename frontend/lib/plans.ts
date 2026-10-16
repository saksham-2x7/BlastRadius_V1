/** Plan definitions shared by the pricing page, the upgrade modal and the settings page (client-safe, no secrets). */

export type Plan = "free" | "pro";

export interface PlanInfo {
  id: Plan;
  name: string;
  price: string;
  period: string;
  blurb: string;
  features: { text: string; included: boolean; soon?: boolean }[];
}

export const PLANS: Record<Plan, PlanInfo> = {
  free: {
    id: "free",
    name: "Basic",
    price: "$0",
    period: "forever",
    blurb: "Scan, understand your attack paths and fix them by hand.",
    features: [
      { text: "Attack-path scan on your graph", included: true },
      { text: "Findings ranked by attack paths", included: true },
      { text: "Manual fixes: Apply or Approve each one", included: true },
      { text: "Applied-fix history with rollback notes", included: true },
      { text: "Auto-fix all safe", included: false },
    ],
  },
  pro: {
    id: "pro",
    name: "Pro",
    price: "$29",
    period: "per month",
    blurb: "Let BlastRadius clear every safe fix in one click.",
    features: [
      { text: "Everything in Basic", included: true },
      { text: "Auto-fix all safe: one click, re-checked after every fix", included: true },
      { text: "High-risk fixes still wait for your approval", included: true },
      { text: "Scheduled scans", included: true, soon: true },
    ],
  },
};

export const isPlan = (v: unknown): v is Plan => v === "free" || v === "pro";
