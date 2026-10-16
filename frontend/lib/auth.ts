import type { NextAuthOptions } from "next-auth";
import GoogleProvider from "next-auth/providers/google";
import { getAccount, setAccount } from "@/lib/subscription";
import { isPlan } from "@/lib/plans";

if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
  console.warn("[auth] GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET missing — Google sign-in will fail. See .env.example.");
}

export const authOptions: NextAuthOptions = {
  providers: [
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID ?? "",
      clientSecret: process.env.GOOGLE_CLIENT_SECRET ?? "",
    }),
  ],
  // JWT cookie sessions. Subscription state lives in FalkorDB and is re-read into the token (see jwt callback).
  session: { strategy: "jwt", maxAge: 60 * 60 * 24 * 7 },
  secret: process.env.NEXTAUTH_SECRET,
  pages: { signIn: "/", error: "/" },
  callbacks: {
    async jwt({ token, account, user, trigger }) {
      if (account) token.provider = account.provider;
      // The plan is only ever read from the database (never from client-sent data). Refresh on sign-in,
      // on session.update(), and at most once a minute otherwise. If the engine is down, keep the last known plan.
      const stale = !token.planAt || Date.now() - token.planAt > 60_000;
      if (token.sub && (account || trigger === "update" || !token.plan || stale)) {
        try {
          const acct = await getAccount(token.sub);
          if (account && acct.updated_at === null) await setAccount({ userId: token.sub, plan: "free", email: user?.email });
          token.plan = isPlan(acct.plan) ? acct.plan : "free";
          token.planAt = Date.now();
        } catch {
          token.plan ??= "free";
        }
      }
      return token;
    },
    async session({ session, token }) {
      if (session.user) {
        session.user.id = token.sub ?? "";
        session.user.plan = isPlan(token.plan) ? token.plan : "free";
        session.user.provider = token.provider;
      }
      return session;
    },
  },
};
