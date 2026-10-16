import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { EngineError, engineFetch } from "@/lib/engine";
import { getAccount } from "@/lib/subscription";
import { WORKSPACE_COOKIE, workspaceHeaders } from "@/lib/workspace";

// Only these engine endpoints are reachable from the browser, and only with a valid session.
const ALLOWED = new Set(["GET scan", "POST fix/auto", "POST fix/auto-all", "POST fix/approve", "POST reset", "POST import"]);
const MAX_IMPORT_BYTES = 300_000;
// Pro-only routes: the plan is read fresh from the database on every call (fails closed), never from the cookie.
const PRO_ONLY = new Set(["POST fix/auto-all"]);

async function proxy(req: Request, ctx: { params: Promise<{ path: string[] }> }) {
  const session = await getServerSession(authOptions);
  if (!session?.user) {
    return NextResponse.json({ error: "unauthorized", message: "Sign in required." }, { status: 401 });
  }
  const { path } = await ctx.params;
  const route = path.join("/");
  // Switching back to the shared sample is just dropping the cookie; nothing to call on the engine.
  if (route === "workspace/sample" && req.method === "POST") {
    const res = NextResponse.json({ ok: true });
    res.cookies.delete(WORKSPACE_COOKIE);
    return res;
  }
  if (!ALLOWED.has(`${req.method} ${route}`)) {
    return NextResponse.json({ error: "not_found", message: "Unknown engine route." }, { status: 404 });
  }

  try {
    if (PRO_ONLY.has(`${req.method} ${route}`) && (await getAccount(session.user.id)).plan !== "pro") {
      return NextResponse.json(
        { error: "upgrade_required", kind: "upgrade_required", message: "Auto-fix all safe is a Pro feature." },
        { status: 402 }
      );
    }
    const body = req.method === "POST" ? await req.text() : undefined;
    if (route === "import" && (body?.length ?? 0) > MAX_IMPORT_BYTES) {
      return NextResponse.json({ error: "rejected", kind: "rejected", message: "That file is too large (300 KB max)." }, { status: 413 });
    }
    const headers = route === "import" ? { "X-Workspace": session.user.id } : await workspaceHeaders(session.user.id);
    const data = await engineFetch<unknown>(`/api/${route}`, { method: req.method, body: body || undefined, headers });
    const res = NextResponse.json(data);
    if (route === "import") {
      res.cookies.set(WORKSPACE_COOKIE, "own", { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/", maxAge: 60 * 60 * 24 * 7 });
    }
    return res;
  } catch (err) {
    if (err instanceof EngineError) {
      return NextResponse.json({ ...err.info, error: err.info.kind }, { status: err.info.status });
    }
    return NextResponse.json({ error: "unknown", kind: "unknown", message: "Unexpected error." }, { status: 500 });
  }
}

export { proxy as GET, proxy as POST };
