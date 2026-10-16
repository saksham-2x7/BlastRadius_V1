/** Wire format shared by the chat route, the providers and the AdvisorPanel (client-safe, no secrets). */

export type ChatRole = "user" | "assistant";

export interface ChatMessage {
  role: ChatRole;
  content: string;
}

/** One line of the NDJSON stream sent by POST /api/chat. */
export type AdvisorEvent =
  | { type: "tool_call"; id: string; name: string; args: Record<string, unknown> }
  | { type: "tool_result"; id: string; name: string; ok: boolean; summary: string; routes?: string[][] }
  | { type: "text"; delta: string }
  | { type: "done" }
  | { type: "error"; message: string };

export const CHAT_LIMITS = { maxMessages: 20, maxChars: 2000 } as const;
