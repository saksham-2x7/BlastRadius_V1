import { NextResponse } from "next/server";
import { EngineError } from "@/lib/engine";
import { billingMode } from "@/lib/stripe";
import { currentUser, fail, unauthorized } from "@/lib/session";
import { setAccount } from "@/lib/subscription";

/** Mock portal "cancel subscription". With real Stripe, cancellation happens in Stripe's portal + webhook. */
export async function POST() {
  if (billingMode !== "mock") return fail(404, "not_found", "Not available.");
  const user = await currentUser();
  if (!user) return unauthorized();
  try {
    await setAccount({ userId: user.id, plan: "free", email: user.email });
    return NextResponse.json({ plan: "free" });
  } catch (err) {
    if (err instanceof EngineError) return NextResponse.json({ ...err.info, error: err.info.kind }, { status: err.info.status });
    return fail(500, "unknown", "Could not cancel the plan.");
  }
}
