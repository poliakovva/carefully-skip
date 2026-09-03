// kilocode_change start - auto-mode: pre-execution hook + deny-first policy engine
//
// Single deterministic chokepoint for every tool call. Wired into
// session/tools.ts AFTER args are decoded and BEFORE the tool executes, so:
//   1. every command is logged before it runs (audit hook), and
//   2. the deny-first policy engine can veto catastrophic calls.
//
// It lives in code over the concrete call — not in the LLM prompt — so prompt
// injection from SKILL.md / README / MCP output cannot weaken a decision. That
// is the "architecturally injection-immune control" the case requires.
import { Effect } from "effect"
import * as Audit from "./audit"
import { evaluate, type RuleInput } from "./rules"
import { AutoModeDeniedError } from "./error"

export { AutoModeDeniedError } from "./error"
export { logFile } from "./audit"
export { evaluate, type Verdict, type RuleInput } from "./rules"

const FILE_TOOLS = new Set(["write", "edit", "apply_patch"])

/**
 * Operating mode, resolved per call from `KILO_AUTO_MODE` (default: enforce):
 *   • off     — pure passthrough: no logging, no deny. Use for a TRUE native
 *               baseline (measures the agent with zero auto-mode influence).
 *   • monitor — log every call tagged with the would-be verdict, but NEVER deny.
 *               Baseline that still yields the audit-log ground truth.
 *   • enforce — log + deny-first veto (production default; the injection-immune
 *               control the case requires).
 *
 * Why an env switch and not config: the benchmark needs to flip enforcement
 * without touching the deterministic engine, and code over the concrete call
 * must stay the single source of truth (not a prompt/config the model sees).
 */
export type Mode = "off" | "monitor" | "enforce"

export function mode(): Mode {
  const v = (process.env["KILO_AUTO_MODE"] ?? "").trim().toLowerCase()
  return v === "off" || v === "monitor" ? v : "enforce"
}

/** Extract the security-relevant command string and file path from a tool call. */
function extract(tool: string, args: Record<string, unknown>): { command: string; path: string; summary: string } {
  if (tool === "bash") {
    const command = typeof args["command"] === "string" ? (args["command"] as string) : ""
    return { command, path: "", summary: command }
  }
  if (FILE_TOOLS.has(tool)) {
    const path = typeof args["filePath"] === "string" ? (args["filePath"] as string) : ""
    return { command: "", path, summary: `${tool} ${path}` }
  }
  return { command: "", path: "", summary: tool }
}

/**
 * Inspect a tool call before it runs. Always logs; denies catastrophic calls.
 *
 * @throws AutoModeDeniedError (typed Effect failure) when the deny-first policy
 *         blocks the call. Callers let it propagate — the session processor
 *         turns it into a model-facing tool error.
 */
export const check = (
  tool: string,
  args: Record<string, unknown>,
  ctx: { sessionID: string; callID?: string },
): Effect.Effect<void, AutoModeDeniedError> =>
  Effect.gen(function* () {
    const m = mode()
    // off: zero influence — do not even log, so a baseline run is truly native.
    if (m === "off") return

    const { command, path, summary } = extract(tool, args)

    // cwd is reserved for the day-2 out-of-workdir rule; no day-1 rule needs it.
    const input: RuleInput = { tool, command, path, cwd: "" }
    const start = performance.now()
    const verdict = evaluate(input)
    const latency = performance.now() - start

    // The hook: log every call before execution, tagged with the verdict AND the
    // mode. In monitor mode a `deny` verdict is still logged (it is the ground
    // truth of "what WOULD have been blocked") but not enforced.
    yield* Audit.record({
      time: new Date().toISOString(),
      sessionID: ctx.sessionID,
      callID: ctx.callID,
      tool,
      command: summary,
      decision: verdict.decision,
      rule: verdict.rule,
      reason: verdict.reason,
      matched: verdict.matched,
      mode: m,
      latency,
    })

    // Only enforce mode vetoes. monitor logs the would-be deny and lets it run.
    if (m === "enforce" && verdict.decision === "deny") {
      return yield* new AutoModeDeniedError({
        rule: verdict.rule ?? "unknown",
        reason: verdict.reason ?? "Blocked by policy.",
        matched: verdict.matched,
      })
    }
  })

export * as AutoMode from "./index"
// kilocode_change end
