import "server-only";
import { engineFetch } from "@/lib/engine";
import { isPlan, type Plan } from "@/lib/plans";

/** Subscription state lives in FalkorDB (:User nodes, separate graph), written only from the server. */
export interface Account {
  user_id: string;
  plan: Plan;
  email: string | null;
  customer_id: string | null;
  updated_at: number | null;
}

export async function getAccount(userId: string): Promise<Account> {
  const a = await engineFetch<Account>(`/api/account/${encodeURIComponent(userId)}`);
  return { ...a, plan: isPlan(a.plan) ? a.plan : "free" };
}

/** Like getAccount, but never throws: an unreachable engine reads as Free (UI display only, never for access checks). */
export async function getPlanOrFree(userId: string): Promise<Plan> {
  try {
    return (await getAccount(userId)).plan;
  } catch {
    return "free";
  }
}

export async function setAccount(input: {
  userId: string;
  plan: Plan;
  email?: string | null;
  customerId?: string | null;
}): Promise<Account> {
  return engineFetch<Account>("/api/account", {
    method: "POST",
    body: JSON.stringify({
      user_id: input.userId,
      plan: input.plan,
      email: input.email ?? null,
      customer_id: input.customerId ?? null,
    }),
  });
}

export async function findUserByCustomer(customerId: string): Promise<string | null> {
  const r = await engineFetch<{ user_id: string | null }>(`/api/account-by-customer/${encodeURIComponent(customerId)}`);
  return r.user_id;
}
