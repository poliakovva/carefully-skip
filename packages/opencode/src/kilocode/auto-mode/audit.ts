// kilocode_change start - auto-mode audit log
import { appendFile } from "node:fs/promises"
import path from "node:path"
import { Effect } from "effect"
import { Global } from "@opencode-ai/core/global"
import type { Verdict } from "./rules"

/**
 * One audit record per intercepted tool call, written BEFORE the tool executes.
 * This is the "log every command before it runs" hook: it is the ground truth
 * the benchmark harness reads to compute ASR / Friction, and the trace a human
 * uses to see exactly what the agent tried to do and what the policy decided.
 */
export interface Entry {
  time: string
  sessionID: string
  callID?: string
  tool: string
  /** Shell command (bash) or a short summary of the file target for file tools. */
  command: string
  decision: Verdict["decision"]
  rule?: string
  reason?: string
  matched?: string
  /** Operating mode that produced this entry: off | monitor | enforce. */
  mode?: string
}

const FILE = path.join(Global.Path.log, "auto-mode.jsonl")

/**
 * Append one entry. Best-effort: audit logging must never break or block a tool
 * call, so any fs error is swallowed (still surfaced to the structured logger).
 */
export const record = (entry: Entry): Effect.Effect<void> =>
  Effect.gen(function* () {
    // Structured log line for live tailing (KILO_PRINT_LOGS / log files).
    yield* Effect.logInfo("auto-mode", {
      tool: entry.tool,
      decision: entry.decision,
      ...(entry.mode ? { mode: entry.mode } : {}),
      ...(entry.rule ? { rule: entry.rule } : {}),
      command: entry.command.slice(0, 500),
    })
    yield* Effect.promise(() => appendFile(FILE, JSON.stringify(entry) + "\n")).pipe(Effect.catch(() => Effect.void))
  })

export const logFile = FILE
// kilocode_change end
