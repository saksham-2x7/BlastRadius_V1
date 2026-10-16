import type { DefaultSession } from "next-auth";
import type { Plan } from "@/lib/plans";

declare module "next-auth" {
  interface Session {
    user: { id: string; plan: Plan; provider?: string } & DefaultSession["user"];
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    provider?: string;
    plan?: Plan;
    planAt?: number;
  }
}
