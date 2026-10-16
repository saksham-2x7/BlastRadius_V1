import "server-only";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { BACKEND_URL } from "@/lib/engine";
import type { ToolSource, ToolSpec } from "./tools";

/**
 * A real MCP client for the engine's streamable-HTTP endpoint (<BACKEND_URL>/mcp/). It connects lazily on first use and
 * must be closed after the request. ENGINE_API_KEY is sent only to our own backend and never reaches the LLM provider.
 */
export function mcpToolSource(workspaceUserId?: string): ToolSource {
  let client: Client | null = null;

  async function connect(): Promise<Client> {
    if (client) return client;
    const transport = new StreamableHTTPClientTransport(new URL("/mcp/", BACKEND_URL), {
      requestInit: {
        headers: {
          ...(process.env.ENGINE_API_KEY ? { "X-Engine-Key": process.env.ENGINE_API_KEY } : {}),
          ...(workspaceUserId ? { "X-Workspace": workspaceUserId } : {}), // the agent works on the user's own graph
        },
      },
    });
    const c = new Client({ name: "blastradius-advisor", version: "1.0.0" });
    try {
      await c.connect(transport);
    } catch {
      throw new Error("Could not reach the MCP server on the engine. Check BACKEND_URL, ENGINE_API_KEY and that the backend is running.");
    }
    client = c;
    return c;
  }

  return {
    async list(): Promise<ToolSpec[]> {
      const { tools } = await (await connect()).listTools();
      return tools.map((t) => ({ name: t.name, description: t.description ?? "", input_schema: t.inputSchema as Record<string, unknown> }));
    },

    async call(name, args) {
      const result = await (await connect()).callTool({ name, arguments: args });
      const text = (result.content as { type: string; text?: string }[] | undefined)?.find((c) => c.type === "text")?.text ?? "";
      if (result.isError) throw new Error(text || "Tool call failed.");
      if (result.structuredContent) return result.structuredContent;
      return JSON.parse(text);
    },

    async close() {
      await client?.close().catch(() => undefined);
      client = null;
    },
  };
}
