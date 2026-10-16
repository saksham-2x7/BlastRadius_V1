import type { ReactNode } from "react";
import Navbar from "./Navbar";

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <div className="relative flex min-h-screen flex-col overflow-x-clip">
      <Navbar />
      <main className="flex-1">{children}</main>
      <footer className="border-t border-line">
        <div className="mx-auto flex max-w-7xl flex-col gap-2 px-4 py-8 text-sm text-muted sm:flex-row sm:items-center sm:justify-between sm:px-6">
          <span>© 2026 BlastRadius. Graph-native exposure management.</span>
          <span className="font-mono text-xs">built on FalkorDB · MCP-ready</span>
        </div>
      </footer>
    </div>
  );
}
