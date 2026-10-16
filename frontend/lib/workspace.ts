import "server-only";
import { cookies } from "next/headers";

/** Cookie set after a successful import. The user's id is what selects their private graph on the engine. */
export const WORKSPACE_COOKIE = "br-ws";

/** Headers that point engine calls at the signed-in user's own imported workspace (none = the shared sample). */
export async function workspaceHeaders(userId: string): Promise<Record<string, string> | undefined> {
  const own = (await cookies()).get(WORKSPACE_COOKIE)?.value === "own";
  return own ? { "X-Workspace": userId } : undefined;
}
