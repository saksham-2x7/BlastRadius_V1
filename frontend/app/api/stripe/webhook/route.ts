import { NextResponse } from "next/server";
import type Stripe from "stripe";
import { billingMode, stripe } from "@/lib/stripe";
import { findUserByCustomer, setAccount } from "@/lib/subscription";

/** Stripe webhook: keeps the plan in sync when subscriptions renew, lapse or are cancelled. Real Stripe mode only. */
export async function POST(req: Request) {
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (billingMode !== "stripe" || !secret) return NextResponse.json({ error: "not_configured" }, { status: 404 });

  const signature = req.headers.get("stripe-signature");
  if (!signature) return NextResponse.json({ error: "missing_signature" }, { status: 400 });

  let event: Stripe.Event;
  try {
    event = stripe().webhooks.constructEvent(await req.text(), signature, secret); // raw body required
  } catch {
    return NextResponse.json({ error: "invalid_signature" }, { status: 400 });
  }

  try {
    if (event.type === "checkout.session.completed") {
      const cs = event.data.object as Stripe.Checkout.Session;
      const userId = cs.client_reference_id;
      const customerId = typeof cs.customer === "string" ? cs.customer : cs.customer?.id ?? null;
      if (userId && cs.status === "complete") await setAccount({ userId, plan: "pro", customerId });
    } else if (event.type === "customer.subscription.updated" || event.type === "customer.subscription.deleted") {
      const sub = event.data.object as Stripe.Subscription;
      const customerId = typeof sub.customer === "string" ? sub.customer : sub.customer.id;
      const userId = sub.metadata?.user_id || (await findUserByCustomer(customerId));
      if (userId) {
        const active = event.type !== "customer.subscription.deleted" && (sub.status === "active" || sub.status === "trialing");
        await setAccount({ userId, plan: active ? "pro" : "free", customerId });
      }
    }
  } catch (err) {
    console.error("[stripe/webhook]", event.type, err);
    return NextResponse.json({ error: "handler_failed" }, { status: 500 }); // Stripe will retry
  }
  return NextResponse.json({ received: true });
}
