import type { Metadata } from "next";
import LoginRedirect from "@/components/landing/LoginRedirect";

export const metadata: Metadata = { title: "Sign in · BlastRadius", robots: { index: false } };

export default function LoginPage() {
  return <LoginRedirect />;
}
