import "server-only";
import Stripe from "stripe";

/**
 * Billing runs in one of two modes:
 *  - "stripe": STRIPE_SECRET_KEY (+ STRIPE_PRICE_PRO) set. Real Stripe Checkout, Billing Portal and webhooks.
 *  - "mock":   no keys. A built-in simulated checkout, so the whole flow works offline with no real payment.
 */
export const billingMode: "stripe" | "mock" = process.env.STRIPE_SECRET_KEY ? "stripe" : "mock";

let client: Stripe | null = null;
export function stripe(): Stripe {
  if (!process.env.STRIPE_SECRET_KEY) throw new Error("STRIPE_SECRET_KEY is not set");
  client ??= new Stripe(process.env.STRIPE_SECRET_KEY);
  return client;
}

export function appUrl(): string {
  return (process.env.NEXTAUTH_URL ?? "http://localhost:3000").replace(/\/$/, "");
}
