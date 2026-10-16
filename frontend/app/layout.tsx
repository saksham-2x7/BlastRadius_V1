import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono, Inter, Instrument_Serif } from "next/font/google";
import AuthProvider from "@/components/providers/AuthProvider";
import "./globals.css";

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const inter = Inter({ variable: "--font-inter", subsets: ["latin"] });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });
const serif = Instrument_Serif({ variable: "--font-instrument", subsets: ["latin"], weight: "400", style: ["normal", "italic"] });

const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL ?? "https://blastradius-ashy.vercel.app";
const TITLE = "BlastRadius: see the paths. Fix what matters.";
const DESCRIPTION =
  "BlastRadius maps your infrastructure as a graph, finds real attack paths to your crown jewels, and fixes the few weaknesses that cut them.";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: { default: TITLE, template: "%s" },
  description: DESCRIPTION,
  applicationName: "BlastRadius",
  openGraph: {
    type: "website",
    url: "/",
    siteName: "BlastRadius",
    title: TITLE,
    description: DESCRIPTION,
    images: [{ url: "/og.png", width: 1200, height: 630, alt: "BlastRadius: see the paths. Fix what matters." }],
  },
  twitter: {
    card: "summary_large_image",
    title: TITLE,
    description: DESCRIPTION,
    images: ["/og.png"],
  },
};

export const viewport: Viewport = { themeColor: "#f4f2ed" };

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={`${geistSans.variable} ${geistMono.variable} ${serif.variable} ${inter.variable} h-full antialiased`}>
      <body className="min-h-full bg-bg text-fg">
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  );
}
