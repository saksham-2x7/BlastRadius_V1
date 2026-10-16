import { NextResponse } from "next/server";
import { EngineError } from "@/lib/engine";
import { verifyMockToken } from "@/lib/mock-checkout";
import { billingMode } from "@/lib/stripe";
import { currentUser, fail, unauthorized } from "@/lib/session";
import { setAccount } from "@/lib/subscription";

/** Simulated checkout completion. Only exists in mock billing mode; no card data is read or stored. */
export async function POST(req: Request) {
  if (billingMode !== "mock") return fail(404, "not_found", "Not available.");
  const user = await currentUser();
  if (!user) return unauthorized();

  const body = (await req.json().catch(() => null)) as { token?: unknown } | null;
  const claim = typeof body?.token === "string" ? verifyMockToken(body.token) : null;
  if (!claim) return fail(400, "invalid_token", "This checkout link is invalid or has expired.");
  if (claim.uid !== user.id) return fail(403, "wrong_user", "This checkout belongs to a different account.");

  try {
    await setAccount({ userId: user.id, plan: "pro", email: user.email });
    return NextResponse.json({ plan: "pro" });
  } catch (err) {
    if (err instanceof EngineError) return NextResponse.json({ ...err.info, error: err.info.kind }, { status: err.info.status });
    return fail(500, "unknown", "Could not activate the plan.");
  }
}
