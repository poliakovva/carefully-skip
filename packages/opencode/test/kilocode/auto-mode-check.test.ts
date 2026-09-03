import { describe, expect, test } from "bun:test"
import { Effect, Exit } from "effect"
import { readFile } from "node:fs/promises"
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
  })
})
