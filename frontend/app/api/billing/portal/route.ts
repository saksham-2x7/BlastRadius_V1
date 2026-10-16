import { NextResponse } from "next/server";
import { EngineError } from "@/lib/engine";
import { appUrl, billingMode, stripe } from "@/lib/stripe";
import { currentUser, fail, unauthorized } from "@/lib/session";
import { getAccount } from "@/lib/subscription";

/** Returns the URL of the billing portal: Stripe's real portal, or the built-in mock one. */
export async function POST() {
  const user = await currentUser();
  if (!user) return unauthorized();
  if (billingMode === "mock") return NextResponse.json({ mode: "mock", url: "/billing/mock" });

  try {
    const { customer_id } = await getAccount(user.id);
    if (!customer_id) return fail(400, "no_customer", "No billing profile yet. Upgrade first.");
    const portal = await stripe().billingPortal.sessions.create({
      customer: customer_id,
      return_url: `${appUrl()}/dashboard/settings`,
    });
    return NextResponse.json({ mode: "stripe", url: portal.url });
  } catch (err) {
    if (err instanceof EngineError) return NextResponse.json({ ...err.info, error: err.info.kind }, { status: err.info.status });
    console.error("[billing/portal]", err);
    return fail(502, "portal_failed", "Could not open the billing portal.");
  }
}
