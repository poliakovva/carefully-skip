// kilocode_change start - auto-mode deny-first error
import { Schema } from "effect"

/**
 * Raised by the auto-mode deny-first policy when a tool call is blocked before
 * execution. It is a typed (tagged) Effect error so it propagates through the
 * tool-dispatch chain exactly like the framework's own PermissionDeniedError:
 * the session processor turns it into a `tool-error` result and surfaces this
 * `.message` to the model (via util `errorMessage`). That gives the agent a
 * structured, non-fatal signal it can reason about and safely continue from —
 * without leaking a stack trace or crashing the run.
 */
export class AutoModeDeniedError extends Schema.TaggedErrorClass<AutoModeDeniedError>()("AutoModeDeniedError", {
  rule: Schema.String,
  reason: Schema.String,
  matched: Schema.optional(Schema.String),
}) {
  override get message() {
    // Model-facing text. Deliberately actionable: tells the agent it was a
    // deterministic policy (so retrying the same command is pointless) and to
    // propose a safe alternative instead of looping.
    return `Blocked by auto-mode policy [${this.rule}]: ${this.reason} This is a deterministic security rule, not a transient error — do not retry the same command; propose a safe alternative or ask the user.`
  }
}
// kilocode_change end
