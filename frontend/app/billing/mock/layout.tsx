import type { Metadata } from "next";
import type { ReactNode } from "react";

export const metadata: Metadata = { title: "Billing portal · BlastRadius", robots: { index: false } };

export default function BillingMockLayout({ children }: { children: ReactNode }) {
  return children;
}
