import { describe, expect, test } from "bun:test"
import { Effect, Exit } from "effect"
import { mkdtemp, readFile, rm } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { AutoMode } from "@/kilocode/auto-mode"
import { AutoModeDeniedError } from "@/kilocode/auto-mode/error"

// kilocode_change - end-to-end: check() denies + logs before execution

const ctx = { sessionID: "ses_test", callID: "call_test" }

describe("AutoMode.check (chokepoint entry)", () => {
  test("denies a catastrophic command with a typed error", async () => {
    // The deny surfaces as a typed AutoModeDeniedError in the error channel,
    // which is exactly what the session processor turns into a tool error.
    const err = await Effect.runPromise(
      AutoMode.check("bash", { command: "rm -rf /" }, ctx).pipe(
        Effect.map(() => null as AutoModeDeniedError | null),
        Effect.catchTag("AutoModeDeniedError", (e) => Effect.succeed(e)),
      ),
    )
    expect(err).toBeInstanceOf(AutoModeDeniedError)
    expect(err!.rule).toBe("rm-rf-root")
    // message is what the model sees — must explain + discourage retry
    expect(err!.message).toContain("auto-mode policy")
    expect(err!.message).toContain("do not retry")
  })

  test("allows a benign command", async () => {
    const exit = await Effect.runPromiseExit(AutoMode.check("bash", { command: "ls -la" }, ctx))
    expect(Exit.isSuccess(exit)).toBe(true)
  })

  test("monitor mode logs the would-be deny but does NOT block", async () => {
    const prev = process.env["KILO_AUTO_MODE"]
    process.env["KILO_AUTO_MODE"] = "monitor"
    try {
      expect(AutoMode.mode()).toBe("monitor")
      const marker = "rm -rf / # monitor-probe-" + Math.floor(performance.now())
      // A catastrophic command succeeds (no deny) in monitor mode …
      const exit = await Effect.runPromiseExit(AutoMode.check("bash", { command: marker }, ctx))
      expect(Exit.isSuccess(exit)).toBe(true)
      // … yet it is still recorded with decision=deny + mode=monitor (ground truth).
      const contents = await readFile(AutoMode.logFile, "utf8").catch(() => "")
      const line = contents
        .trim()
        .split("\n")
        .map((l) => {
          try {
            return JSON.parse(l)
          } catch {
            return null
          }
        })
        .filter(Boolean)
        .find((e) => e.command === marker)
      expect(line).toBeTruthy()
      expect(line.decision).toBe("deny")
      expect(line.rule).toBe("rm-rf-root")
      expect(line.mode).toBe("monitor")
    } finally {
      if (prev === undefined) delete process.env["KILO_AUTO_MODE"]
      else process.env["KILO_AUTO_MODE"] = prev
    }
  })

  test("off mode is a pure passthrough — no deny, no log entry", async () => {
    const prev = process.env["KILO_AUTO_MODE"]
    process.env["KILO_AUTO_MODE"] = "off"
    try {
      expect(AutoMode.mode()).toBe("off")
      const marker = "rm -rf / # off-probe-" + Math.floor(performance.now())
      const exit = await Effect.runPromiseExit(AutoMode.check("bash", { command: marker }, ctx))
      expect(Exit.isSuccess(exit)).toBe(true)
      const contents = await readFile(AutoMode.logFile, "utf8").catch(() => "")
      expect(contents.includes(marker)).toBe(false)
    } finally {
      if (prev === undefined) delete process.env["KILO_AUTO_MODE"]
      else process.env["KILO_AUTO_MODE"] = prev
    }
  })

  test("writes an audit entry before execution (the hook)", async () => {
    const marker = "echo audit-probe-" + Math.floor(performance.now())
    await Effect.runPromise(AutoMode.check("bash", { command: marker }, ctx))
    const contents = await readFile(AutoMode.logFile, "utf8").catch(() => "")
    const line = contents
      .trim()
      .split("\n")
      .map((l) => {
        try {
          return JSON.parse(l)
        } catch {
          return null
        }
      })
      .filter(Boolean)
      .find((e) => e.command === marker)
    expect(line).toBeTruthy()
    expect(line.tool).toBe("bash")
    expect(line.decision).toBe("allow")
    expect(line.sessionID).toBe("ses_test")
    expect(typeof line.time).toBe("string")
    expect(typeof line.latency).toBe("number")
    expect(line.latency).toBeGreaterThanOrEqual(0)
  })

  test("can isolate benchmark audit output", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "kilo-auto-mode-"))
    const file = path.join(dir, "audit.jsonl")
    const prev = process.env["KILO_AUTO_MODE_AUDIT_FILE"]
    process.env["KILO_AUTO_MODE_AUDIT_FILE"] = file
    try {
      const marker = "echo isolated-probe-" + Math.floor(performance.now())
      await Effect.runPromise(AutoMode.check("bash", { command: marker }, ctx))
      const contents = await readFile(file, "utf8")
      expect(contents).toContain(marker)
    } finally {
      if (prev === undefined) delete process.env["KILO_AUTO_MODE_AUDIT_FILE"]
      if (prev !== undefined) process.env["KILO_AUTO_MODE_AUDIT_FILE"] = prev
      await rm(dir, { recursive: true, force: true })
    }
  })
})
