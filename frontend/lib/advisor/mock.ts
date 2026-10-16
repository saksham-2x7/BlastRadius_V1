import "server-only";
import type { AdvisorProvider } from "./provider";
import type { AdvisorEvent } from "./types";
import { summarize, toolErrorMessage, type ToolSource } from "./tools";
import { fmtEpssText } from "./format";
import type { ApplyResult, AttackPathsResult, ChokeResult, ContextResult, ExplainResult, RankedFinding, RecallResult, SimulateResult, TicketResult, FileResult } from "./results";

/**
 * Mock "LLM": picks tools with simple keyword rules and writes its answer from REAL tool results (templated text).
 * It exists to exercise the whole pipeline (route, streaming, tool-call UI) before a model is connected.
 */
const REF = /\b(F\d{1,3}|CVE-\d{4}-\d{4,7})\b/i;
const sleep = (ms: number, signal: AbortSignal) =>
  new Promise<void>((res) => {
    const t = setTimeout(res, ms);
    signal.addEventListener("abort", () => (clearTimeout(t), res()), { once: true });
  });

async function* say(text: string, signal: AbortSignal): AsyncGenerator<AdvisorEvent> {
  for (const chunk of text.match(/\S+\s*|\n/g) ?? []) {
    if (signal.aborted) return;
    yield { type: "text", delta: chunk };
    await sleep(chunk === "\n" ? 30 : 22, signal);
  }
}

const rank = (a: RankedFinding, b: RankedFinding) => b.attack_paths - a.attack_paths || Number(b.kev) - Number(a.kev) || b.epss - a.epss;

export const mockProvider: AdvisorProvider = {
  name: "mock",
  async *stream(messages, tools: ToolSource, signal) {
    const q = [...messages].reverse().find((m) => m.role === "user")?.content ?? "";
    const lower = q.toLowerCase();
    let n = 0;

    // Calls a tool and emits the tool_call / tool_result events the UI renders.
    async function* call<T>(name: string, args: Record<string, unknown>, out: { value?: T }): AsyncGenerator<AdvisorEvent> {
      const id = `t${++n}`;
      yield { type: "tool_call", id, name, args };
      try {
        const result = await tools.call(name, args);
        out.value = result as T;
        yield { type: "tool_result", id, name, ok: true, summary: summarize(name, result) };
      } catch (err) {
        yield { type: "tool_result", id, name, ok: false, summary: toolErrorMessage(err) };
      }
    }

    await sleep(250, signal);
    const ref = q.match(REF)?.[1]?.toUpperCase();

    // 0e) file it for real (only when explicitly asked)
    if (/\b(file|open|create|submit|push|send)\b.*\b(github issue|issue|ticket)\b/.test(lower) && !/draft/.test(lower)) {
      let target = ref;
      if (!target) {
        const ov: { value?: AttackPathsResult } = {};
        yield* call("get_attack_paths", { limit: 10 }, ov);
        target = (ov.value?.top_findings ?? []).filter((f) => !f.patched && f.attack_paths > 0).sort(rank)[0]?.finding_id;
      }
      if (!target) return void (yield* say("No finding sits on an attack path, so there is nothing to file.", signal));
      const fr: { value?: FileResult } = {};
      yield* call("file_github_issue", { finding_id: target }, fr);
      if (!fr.value) return void (yield* say(`I couldn't file an issue for ${target}.`, signal));
      yield* say(fr.value.filed ? `Filed a real GitHub issue for ${target}: ${fr.value.url}\n\n**${fr.value.title}**` : `${fr.value.message}\n\nAsk me to "draft a ticket for ${target}" to get the text.`, signal);
      return;
    }

    // 0d) draft a ticket
    if (/ticket|jira|github issue|\bissue\b|open a pr|file (a|an)/.test(lower)) {
      let target = ref;
      if (!target) {
        const ov: { value?: AttackPathsResult } = {};
        yield* call("get_attack_paths", { limit: 10 }, ov);
        target = (ov.value?.top_findings ?? []).filter((f) => !f.patched && f.attack_paths > 0).sort(rank)[0]?.finding_id;
      }
      if (!target) return void (yield* say("No finding sits on an attack path, so there is nothing to file a ticket for.", signal));
      const tk: { value?: TicketResult } = {};
      yield* call("draft_fix_ticket", { finding_id: target, format: /jira/.test(lower) ? "jira" : "github" }, tk);
      if (!tk.value) return void (yield* say(`I couldn't draft a ticket for ${target}.`, signal));
      yield* say(`Here is a ready-to-file ${tk.value.format} ticket (nothing was sent anywhere):\n\n**${tk.value.title}**\nLabels: ${tk.value.labels.join(", ")} · Assignee: ${tk.value.assignee_hint}\n\n${tk.value.body_markdown.replace(/^#+ /gm, "")}`, signal);
      return;
    }

    // 0a) act on one finding, or on everything that is safe
    if (/\b(apply|do it|go ahead|execute|clean up|cleanup|remediate|act on|auto.?fix|fix (all|everything|what))/.test(lower)) {
      const ov: { value?: AttackPathsResult } = {};
      yield* call("get_attack_paths", { limit: 20 }, ov);
      if (!ov.value) return void (yield* say("I couldn't read the attack graph. Is the engine running?", signal));
      const open = ov.value.top_findings.filter((f) => !f.patched && f.attack_paths > 0).sort(rank);
      const targets = ref ? open.filter((f) => f.finding_id === ref || f.cve_id === ref) : open;
      if (!targets.length) return void (yield* say(ref ? `${ref} is already patched or is not on an attack path, so there is nothing to apply.` : "No finding sits on an attack path, so there is nothing to act on.", signal));
      const done: ApplyResult[] = [];
      for (const f of targets) {
        const sim: { value?: SimulateResult } = {};
        yield* call("simulate_fix", { finding_id: f.finding_id }, sim);
        const act: { value?: ApplyResult } = {};
        yield* call("apply_safe_fix", { finding_id: f.finding_id, reason: sim.value?.verdict ?? "user asked to clean up safe findings" }, act);
        if (act.value) done.push(act.value);
      }
      const applied = done.filter((d) => d.decision === "applied");
      const waiting = done.filter((d) => d.decision === "needs_human_approval");
      yield* say(
        (applied.length ? `I applied ${applied.length} low-risk fix${applied.length === 1 ? "" : "es"}:\n${applied.map((d) => `• ${d.finding_id} · ${d.cve_id} on \`${d.host}\`: attack paths ${d.paths_before} → ${d.paths_after}`).join("\n")}\n\n` : "I did not apply anything.\n\n") +
          (waiting.length ? `Waiting for a human (high blast radius, I will not apply these myself):\n${waiting.map((d) => `• ${d.finding_id} · ${d.cve_id} on \`${d.host}\`. Approve it in the Fix queue.`).join("\n")}\n\n` : "") +
          `Every decision was saved to my graph memory.`,
        signal
      );
      return;
    }

    // 0b) FalkorDB graph algorithms
    if (/choke|bottleneck|central|betweenness|where (do|would) .*cut/.test(lower)) {
      const ck: { value?: ChokeResult } = {};
      yield* call("get_choke_points", { limit: 4 }, ck);
      if (!ck.value) return void (yield* say("I couldn't run the graph algorithm. Is the engine running?", signal));
      yield* say(
        `Ranked by live attack paths, with FalkorDB's betweenness-centrality and PageRank algorithms as the structural signal:\n\n` +
          ck.value.ranking.map((h, i) => `${i + 1}. \`${h.host}\`: betweenness ${h.betweenness}, PageRank ${h.pagerank}, ${h.attack_paths} live attack ${h.attack_paths === 1 ? "path" : "paths"}`).join("\n") +
          `\n\n${ck.value.note}`,
        signal
      );
      return;
    }
    if (/shortest|route|how (would|could|can) an attacker|show .*path|explain .*path/.test(lower)) {
      const ex: { value?: ExplainResult } = {};
      yield* call("explain_attack_path", { routes: 3 }, ex);
      if (!ex.value) return void (yield* say("I couldn't compute the routes. Is the engine running?", signal));
      yield* say(
        `Shortest routes from the internet to the crown jewel (FalkorDB shortest-path algorithm):\n\n` +
          ex.value.routes.map((r) => `• ${r.route.join(" → ")} (${r.hops} hops, ${r.still_exploitable ? "still exploitable" : "already cut"})`).join("\n") +
          `\n\n${ex.value.note}`,
        signal
      );
      return;
    }

    // 0c) graph memory
    if (/remember|history|what did you|earlier|last (session|time)|previous|memory|already (did|done)/.test(lower)) {
      const mem: { value?: RecallResult } = {};
      yield* call("recall_agent_memory", { limit: 8 }, mem);
      if (!mem.value) return void (yield* say("I couldn't read my memory. Is the engine running?", signal));
      yield* say(
        mem.value.actions.length
          ? `From my graph memory, newest first:\n\n${mem.value.actions.map((a) => `• ${new Date(a.ts).toLocaleTimeString()} · ${a.finding_id} on \`${a.host}\`: ${a.decision.replace(/_/g, " ")}${a.paths_before >= 0 ? ` (paths ${a.paths_before} → ${a.paths_after})` : ""}. ${a.rationale}`).join("\n")}\n\n${mem.value.note}`
          : "My memory is empty: I have not taken any action yet. Ask me to clean up the safe findings and I will log each decision.",
        signal
      );
      return;
    }

    // 1) what-if on a specific finding
    if (ref && /simulat|what.?if|would|eliminat|remov|patch|fix/.test(lower)) {
      const sim: { value?: SimulateResult } = {};
      yield* call("simulate_fix", { finding_id: ref }, sim);
      if (!sim.value) return void (yield* say(`I couldn't simulate ${ref}. Check that it is a valid finding or CVE id.`, signal));
      const s = sim.value;
      yield* say(
        `${s.verdict}\n\n` +
          (s.eliminated_paths.length ? `Paths removed:\n${s.eliminated_paths.map((p: string[]) => `• ${p.join(" → ")}`).join("\n")}\n\n` : "") +
          `This was a read-only simulation. Nothing was changed.` +
          (s.remaining_paths.length ? ` ${s.remaining_paths.length} path${s.remaining_paths.length === 1 ? "" : "s"} would remain.` : " No attack paths would remain."),
        signal
      );
      return;
    }

    // 2) explain a specific finding
    if (ref) {
      const ctx: { value?: ContextResult } = {};
      yield* call("get_vulnerability_context", { cve_id: ref }, ctx);
      if (!ctx.value) return void (yield* say(`I couldn't find ${ref}. Ask me for the ranked findings to see valid ids.`, signal));
      const c = ctx.value;
      const b = c.blast_radius;
      yield* say(
        `**${c.finding_id} · ${c.cve_id}** on \`${c.host}\` (${c.host_software ?? "unknown software"})\n` +
          `${c.product ? c.product + ": " : ""}${c.summary ?? ""}\n\n` +
          `• CVSS ${c.cvss.toFixed(1)} · EPSS ${fmtEpssText(c.epss)} · CISA KEV: ${c.kev ? "yes" : "no"}\n` +
          `• Blast radius: ${b.attack_paths_through_host} of ${b.total_attack_paths} attack paths${b.reaches_crown_jewel ? ", reaches a crown jewel" : ""}\n` +
          `• Tier: ${c.tier} (${c.tier_reason})\n\n${c.priority_note}`,
        signal
      );
      return;
    }

    // 3) what should I patch first?
    if (/first|priorit|recommend|urgent|riskiest|most (important|critical|dangerous)|top|should i (patch|fix)|where (do|should) i start/.test(lower)) {
      const ov: { value?: AttackPathsResult } = {};
      yield* call("get_attack_paths", { limit: 10 }, ov);
      const open = (ov.value?.top_findings ?? []).filter((f) => !f.patched && f.attack_paths > 0).sort(rank);
      if (!ov.value) return void (yield* say("I couldn't read the attack graph. Is the engine running?", signal));
      if (!open.length) return void (yield* say("No attack paths remain, so there is nothing to patch. Nice work.", signal));

      const top = open[0];
      const sim: { value?: SimulateResult } = {};
      yield* call("simulate_fix", { finding_id: top.finding_id }, sim);
      const decoy = ov.value.top_findings.filter((f) => f.attack_paths === 0 && !f.patched && f.cvss >= 9).sort((a, b) => b.cvss - a.cvss)[0];
      const next = open[1];
      yield* say(
        `Patch **${top.finding_id} · ${top.cve_id}** on \`${top.host}\` first.\n\n` +
          `• It sits on ${top.attack_paths} of ${ov.value.total_attack_paths} attack paths${ov.value.choke_points[0]?.host === top.host ? " and is the choke point" : ""}.\n` +
          `• CISA KEV: ${top.kev ? "yes (exploited in the wild)" : "no"} · EPSS ${fmtEpssText(top.epss)} · CVSS ${top.cvss.toFixed(1)}.\n` +
          (sim.value ? `• Simulation: ${sim.value.verdict}\n` : "") +
          (next ? `\nThen: ${next.finding_id} · ${next.cve_id} on \`${next.host}\` (${next.attack_paths} ${next.attack_paths === 1 ? "path" : "paths"}${next.kev ? ", KEV" : ""}).\n` : "") +
          (decoy ? `\nDe-prioritise ${decoy.cve_id} (CVSS ${decoy.cvss.toFixed(1)}): it is on 0 attack paths, so patching it removes no route to a crown jewel.` : "") +
          (top.tier === "approval" ? `\n\nThis one is high-risk, so it needs your approval in the fix queue.` : `\n\nThis one is low-risk and can be auto-applied.`),
        signal
      );
      return;
    }

    // 4) KEV focus
    if (/kev|known exploited|exploited in the wild|cisa/.test(lower)) {
      const ov: { value?: AttackPathsResult } = {};
      yield* call("get_attack_paths", { limit: 20 }, ov);
      const kev = (ov.value?.top_findings ?? []).filter((f) => f.kev && !f.patched).sort(rank);
      if (!ov.value) return void (yield* say("I couldn't read the attack graph. Is the engine running?", signal));
      yield* say(
        kev.length
          ? `${kev.length} unpatched finding${kev.length === 1 ? " is" : "s are"} in CISA KEV:\n\n` +
              kev.map((f) => `• **${f.finding_id} · ${f.cve_id}** on \`${f.host}\`: CVSS ${f.cvss.toFixed(1)}, EPSS ${fmtEpssText(f.epss)}, ${f.attack_paths} attack ${f.attack_paths === 1 ? "path" : "paths"}`).join("\n") +
              `\n\nKEV means attackers are already using it, but it only matters first if it also sits on a route to a crown jewel.`
          : "No unpatched findings are in CISA KEV.",
        signal
      );
      return;
    }

    // 5) overview
    if (/path|choke|overview|summary|status|exposure|risk|attack|graph/.test(lower)) {
      const ov: { value?: AttackPathsResult } = {};
      yield* call("get_attack_paths", { limit: 10 }, ov);
      if (!ov.value) return void (yield* say("I couldn't read the attack graph. Is the engine running?", signal));
      const v = ov.value;
      yield* say(
        `There ${v.total_attack_paths === 1 ? "is 1 attack path" : `are ${v.total_attack_paths} attack paths`} from the internet to a crown jewel` +
          (v.patched_count ? ` (${v.patched_count} finding${v.patched_count === 1 ? "" : "s"} already patched)` : "") +
          `.\n` +
          (v.choke_points.length ? `Choke point: \`${v.choke_points[0].host}\` carries ${v.choke_points[0].attack_paths} of them.\n` : "") +
          `\nTop findings by attack paths:\n` +
          v.top_findings.slice(0, 4).map((f) => `• ${f.finding_id} ${f.cve_id} on \`${f.host}\`: ${f.attack_paths} ${f.attack_paths === 1 ? "path" : "paths"}${f.kev ? ", KEV" : ""}`).join("\n"),
        signal
      );
      return;
    }

    yield* say(
      "I can analyse your attack graph. Try:\n\n• Which vulnerability should I patch first?\n• Which findings are in CISA KEV?\n• What if I patch <finding id>?\n• Fix everything that is safe\n• Where is the choke point?\n• Draft a Jira ticket for the top finding\n• What did you do earlier?",
      signal
    );
  },
};
