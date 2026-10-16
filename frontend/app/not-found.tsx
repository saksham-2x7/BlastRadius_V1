import type { Metadata } from "next";
import Link from "next/link";
import Layout from "@/components/layout/Layout";

export const metadata: Metadata = { title: "Page not found · BlastRadius", robots: { index: false } };

export default function NotFound() {
  return (
    <Layout>
      <section className="grid min-h-[70vh] place-items-center px-4 pt-24 text-center">
        <div>
          <p className="font-mono text-xs uppercase tracking-widest text-muted">404</p>
          <h1 className="mt-2 text-4xl tracking-tight sm:text-5xl">
            This path leads <em className="font-serif italic text-accent">nowhere</em>.
          </h1>
          <p className="mx-auto mt-3 max-w-sm text-sm text-muted">The page you asked for doesn&apos;t exist, or it moved.</p>
          <Link href="/" className="btn-chrome mt-6 inline-flex h-11 items-center rounded-full px-6 text-sm font-semibold">
            Back to home
          </Link>
        </div>
      </section>
    </Layout>
  );
}
