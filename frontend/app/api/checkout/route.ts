import { NextResponse } from "next/server";
import { EngineError } from "@/lib/engine";
import { createMockToken } from "@/lib/mock-checkout";
import { appUrl, billingMode, stripe } from "@/lib/stripe";
import { currentUser, fail, unauthorized } from "@/lib/session";
import { getAccount } from "@/lib/subscription";

/** Creates a checkout session for the Pro plan and returns the URL to send the browser to. */
export async function POST() {
  const user = await currentUser();
  if (!user) return unauthorized();

  try {
    const account = await getAccount(user.id);
    if (account.plan === "pro") return fail(409, "already_pro", "You are already on the Pro plan.");

    if (billingMode === "mock") {
      return NextResponse.json({ mode: "mock", url: `/checkout/mock?token=${encodeURIComponent(createMockToken(user.id))}` });
    }

    const price = process.env.STRIPE_PRICE_PRO;
    if (!price) return fail(500, "misconfigured", "STRIPE_PRICE_PRO is not set.");
    const session = await stripe().checkout.sessions.create({
      mode: "subscription",
      line_items: [{ price, quantity: 1 }],
      ...(account.customer_id ? { customer: account.customer_id } : { customer_email: user.email || undefined }),
      client_reference_id: user.id,
      metadata: { user_id: user.id },
      subscription_data: { metadata: { user_id: user.id } },
      allow_promotion_codes: true,
      success_url: `${appUrl()}/api/checkout/confirm?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${appUrl()}/pricing?checkout=cancelled`,
    });
    if (!session.url) return fail(502, "stripe_error", "Stripe did not return a checkout URL.");
    return NextResponse.json({ mode: "stripe", url: session.url });
  } catch (err) {
    if (err instanceof EngineError) return NextResponse.json({ ...err.info, error: err.info.kind }, { status: err.info.status });
    console.error("[checkout]", err);
    return fail(502, "checkout_failed", "Could not start checkout. Please try again.");
  }
}
