import { NextResponse } from "next/server";
import { appUrl, billingMode, stripe } from "@/lib/stripe";
import { currentUser } from "@/lib/session";
import { setAccount } from "@/lib/subscription";

/** Stripe success_url target. Verifies the Checkout Session belongs to the signed-in user before upgrading them. */
export async function GET(req: Request) {
  const to = (path: string) => NextResponse.redirect(new URL(path, appUrl()));
  const user = await currentUser();
  const sessionId = new URL(req.url).searchParams.get("session_id");
  if (billingMode !== "stripe" || !user || !sessionId) return to("/pricing");

  try {
    const cs = await stripe().checkout.sessions.retrieve(sessionId);
    const paid = cs.status === "complete" && (cs.payment_status === "paid" || cs.payment_status === "no_payment_required");
    if (cs.client_reference_id !== user.id || !paid) return to("/pricing?checkout=failed");
    const customerId = typeof cs.customer === "string" ? cs.customer : cs.customer?.id ?? null;
    await setAccount({ userId: user.id, plan: "pro", email: user.email, customerId });
    return to("/dashboard/settings?checkout=success");
  } catch (err) {
    console.error("[checkout/confirm]", err);
    return to("/pricing?checkout=failed");
  }
}
