import "server-only";
import { createHmac, timingSafeEqual } from "node:crypto";

/** Short-lived HMAC-signed token binding a simulated checkout to one user, so it can't be forged or reused for others. */
const TTL_MS = 30 * 60 * 1000;

function sign(payload: string): string {
  const secret = process.env.NEXTAUTH_SECRET;
  if (!secret) throw new Error("NEXTAUTH_SECRET is not set");
  return createHmac("sha256", secret).update(payload).digest("base64url");
}

export function createMockToken(userId: string): string {
  const payload = Buffer.from(JSON.stringify({ uid: userId, plan: "pro", exp: Date.now() + TTL_MS })).toString("base64url");
  return `${payload}.${sign(payload)}`;
}

export function verifyMockToken(token: string): { uid: string; plan: "pro" } | null {
  const [payload, sig] = token.split(".");
  if (!payload || !sig) return null;
  const expected = Buffer.from(sign(payload));
  const given = Buffer.from(sig);
  if (expected.length !== given.length || !timingSafeEqual(expected, given)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString());
    if (typeof data.uid !== "string" || data.plan !== "pro" || typeof data.exp !== "number" || data.exp < Date.now()) return null;
    return { uid: data.uid, plan: "pro" };
  } catch {
    return null;
  }
}
