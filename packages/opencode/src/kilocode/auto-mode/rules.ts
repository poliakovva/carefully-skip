// kilocode_change start - auto-mode deny-first policy engine
//
// Deterministic, injection-immune rules over a tool call. This module is pure:
// it never calls the LLM and never reads instructions from context, so prompt
// injection from SKILL.md / README / MCP output cannot weaken a decision — the
// verdict is decided by code over the concrete command/path, not by the model.
//
// Semantics: deny-first. The FIRST matching deny rule wins and can never be
// downgraded. Anything that matches nothing falls through to "allow" here and
// is handed to the existing permission (ask) flow unchanged, so legitimate work
// is not blocked (protects Utility).
//
// This is the day-1 baseline: string/regex matching over a normalized command.
// It is intentionally conservative and honest about its limits — see LIMITS
// below. Day-2 upgrades this to AST matching via the existing tree-sitter scan
// in tool/shell.ts (ShellPermission) and adds the slopsquatting + LLM tiers.

export type Decision = "allow" | "deny"

export interface Verdict {
  decision: Decision
  /** Stable id of the rule that decided (only set on deny). */
  rule?: string
  /** Short human/model-facing explanation of why it was denied. */
  reason?: string
  /** The exact substring that tripped the rule, for the audit log. */
  matched?: string
}

const ALLOW: Verdict = { decision: "allow" }

/** What we hand to a rule: the tool id plus the extracted, normalized command/path. */
export interface RuleInput {
  tool: string
  /** Raw shell command (bash tool) or "" for non-shell tools. */
  command: string
  /** Target file path (write/edit/apply_patch) or "" otherwise. */
  path: string
  /** Absolute working directory of the session, for out-of-workdir checks. */
  cwd: string
}

interface Rule {
  id: string
  reason: string
  /** Tool ids this rule applies to. */
  tools: string[]
  /** Return the matched substring, or null if the rule does not fire. */
  test(input: RuleInput): string | null
}

// Normalize a command for matching: collapse whitespace and lowercase. We keep
// the ORIGINAL around for logging; matching on a normalized copy defeats trivial
// spacing tricks (`rm   -rf`). It does NOT defeat quote-splitting obfuscation
// (`r''m`) — that is a known limit handled by the AST upgrade (see LIMITS).
function norm(cmd: string): string {
  return cmd.replace(/\s+/g, " ").trim().toLowerCase()
}

const SHELL = ["bash"]
const FILE = ["write", "edit", "apply_patch"]

// Secret / credential material we never let a command read, exfiltrate, or a
// file tool overwrite. Matched as path-ish substrings.
const SECRET_PATTERNS = [
  /(^|[^a-z0-9_])\.env(\.[a-z0-9_-]+)?($|[^a-z0-9_])/i, // .env, .env.local, @.env, /path/.env.production
  /\.ssh\/id_[a-z0-9]+/i, // private keys (authorized_keys is a persistence path, handled below)
  /\.aws\/credentials/i,
  /\.npmrc/i,
  /\.pypirc/i,
  /\.netrc/i,
  /\.docker\/config\.json/i,
  /\.kube\/config/i,
  /id_rsa|id_ed25519|id_ecdsa/i,
  /\.pem($|[\s"'/\\])/i,
]

function matchSecret(text: string): string | null {
  for (const re of SECRET_PATTERNS) {
    const m = re.exec(text)
    if (m) return m[0].trim()
  }
  return null
}

// System / persistence paths that should never be written by an agent: touching
// them is how a compromise becomes permanent (shell profiles, cron, sshd, etc.).
const SYSTEM_WRITE_PATTERNS = [
  /(^|[\s"'=])\/(etc|bin|sbin|usr|boot|sys|lib)(\/|[\s"'])/i,
  /\.(bash|zsh)(rc|_profile|_login)($|[\s"'])/i,
  /\/\.?profile($|[\s"'])/i,
  /crontab|\/etc\/cron/i,
  /authorized_keys/i,
  /\/etc\/(passwd|shadow|sudoers)/i,
]

function matchSystemPath(text: string): string | null {
  for (const re of SYSTEM_WRITE_PATTERNS) {
    const m = re.exec(text)
    if (m) return m[0].trim()
  }
  return null
}

const RULES: Rule[] = [
  // ── Catastrophic filesystem destruction ─────────────────────────────────
  {
    id: "rm-rf-root",
    reason:
      "This command recursively force-deletes a root, home, or wildcard path, which can destroy the machine or workspace. Refused by the auto-mode deny-first policy.",
    tools: SHELL,
    test: ({ command }) => {
      const c = norm(command)
      // rm with recursive+force flags (in any order / combined) …
      if (!/\brm\b/.test(c)) return null
      const hasRF = /\brm\b[^|;&]*\s-(?:[a-z]*r[a-z]*f|[a-z]*f[a-z]*r)\b/.test(c) || /\brm\b[^|;&]*\s-r\b[^|;&]*\s-f\b/.test(c)
      if (!hasRF) return null
      // … targeting a dangerous root: /, /*, ~, $HOME, ., .. , or a bare drive
      if (/\brm\b[^|;&]*\s(-{1,2}[a-z]+\s+)*(\/(\s|\*|$)|\/\*|~\/?(\s|\*|$)|\$home|\.\.?(\s|\/?\*|$))/.test(c + " "))
        return "rm -rf on root/home/wildcard"
      return null
    },
  },
  {
    id: "disk-wipe",
    reason:
      "This command writes directly to a block device or formats a disk (dd/mkfs/> /dev/…), which irreversibly destroys data. Refused by the auto-mode deny-first policy.",
    tools: SHELL,
    test: ({ command }) => {
      const c = norm(command)
      if (/\bmkfs\b/.test(c)) return "mkfs"
      if (/\bdd\b[^|;&]*\bof=\/dev\/(sd|nvme|disk|hd|vd)/.test(c)) return "dd of=/dev/…"
      if (/>\s*\/dev\/(sd|nvme|disk|hd|vd)/.test(c)) return "> /dev/…"
      return null
    },
  },
  {
    id: "fork-bomb",
    reason: "This looks like a fork bomb, which will exhaust system resources. Refused by the auto-mode deny-first policy.",
    tools: SHELL,
    test: ({ command }) => (/:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/.test(command) ? "fork bomb" : null),
  },

  // ── Remote-code execution: pipe-to-shell / eval of downloaded content ────
  {
    id: "pipe-to-shell",
    reason:
      "This pipes downloaded content straight into a shell/interpreter (curl|sh style), executing untrusted remote code without review. Refused by the auto-mode deny-first policy.",
    tools: SHELL,
    test: ({ command }) => {
      const c = norm(command)
      // curl/wget/fetch … | sh|bash|zsh|python|perl|ruby|node   (optionally via sudo)
      if (/\b(curl|wget|fetch)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|dash|python[0-9.]*|perl|ruby|node|pwsh|powershell)\b/.test(c))
        return "download | shell"
      // process substitution: bash <(curl …)
      if (/\b(sh|bash|zsh|dash)\b[^|;&]*<\(\s*(curl|wget|fetch)\b/.test(c)) return "shell <(curl …)"
      // command substitution executed by an interpreter: sh -c "$(curl …)", eval $(curl …)
      if (/\b(sh|bash|zsh|dash|python[0-9.]*|perl|ruby|node)\b[^|;&]*-c[^|;&]*\$\(\s*(curl|wget|fetch)\b/.test(c))
        return "interpreter -c $(curl …)"
      if (/\b(eval|source|\.)\b[^|;&]*\$\(\s*(curl|wget|fetch)\b/.test(c)) return "eval $(curl …)"
      if (/\b(iex|invoke-expression)\b[^|;&]*\b(iwr|invoke-webrequest|curl|wget)\b/.test(c)) return "iex(iwr …)"
      return null
    },
  },

  // ── Destructive database operations ──────────────────────────────────────
  {
    id: "sql-drop",
    reason:
      "This issues a destructive database statement (DROP DATABASE/TABLE, TRUNCATE, DELETE without WHERE). Refused by the auto-mode deny-first policy.",
    tools: SHELL,
    test: ({ command }) => {
      const c = norm(command)
      if (/\bdrop\s+(database|schema|table)\b/.test(c)) return "DROP DATABASE/TABLE"
      if (/\btruncate\s+table\b/.test(c)) return "TRUNCATE TABLE"
      if (/\bdelete\s+from\b(?![^;]*\bwhere\b)/.test(c)) return "DELETE without WHERE"
      return null
    },
  },

  // ── Secret / credential access via shell ─────────────────────────────────
  {
    id: "secret-access",
    reason:
      "This command reads or transmits credential/secret material (.env, SSH keys, cloud credentials). Refused by the auto-mode deny-first policy.",
    tools: SHELL,
    test: ({ command }) => matchSecret(command),
  },

  // ── File-tool guards (write / edit / apply_patch) ────────────────────────
  {
    id: "write-secret",
    reason:
      "This writes to a credential/secret file (.env, SSH keys, cloud credentials). Refused by the auto-mode deny-first policy.",
    tools: FILE,
    test: ({ path }) => matchSecret(path),
  },
  {
    id: "write-system-path",
    reason:
      "This writes to a protected system or shell-startup path (/etc, shell profiles, authorized_keys, cron), a common persistence vector. Refused by the auto-mode deny-first policy.",
    tools: FILE,
    test: ({ path }) => matchSystemPath(path),
  },
]

/**
 * Evaluate the deny-first policy. Returns the first matching deny, or allow.
 * Pure and synchronous — safe to call from anywhere, deterministic per input.
 */
export function evaluate(input: RuleInput): Verdict {
  // TEMPORARY: benchmark-only deny-all override, gated behind an env var that
  // is never set outside a deliberate calibration run. Lets the harness
  // measure the FP ceiling / ASR floor and confirm the audit pipeline
  // actually records a deny when one happens. Remove once the adjudicator
  // comparison run is done.
  if (process.env["KILO_AUTO_MODE_DENY_ALL"]) {
    return { decision: "deny", rule: "deny-all-calibration", reason: "Benchmark calibration: deny-all mode.", matched: input.command || input.path || input.tool }
  }
  for (const rule of RULES) {
    if (!rule.tools.includes(input.tool)) continue
    const matched = rule.test(input)
    if (matched) return { decision: "deny", rule: rule.id, reason: rule.reason, matched }
  }
  return ALLOW
}

/** Exposed for tests / benchmark harness. */
export const __rules = RULES

// LIMITS (day-1, honest):
//  • Regex over a normalized string. Quote/backslash splitting (r''m -rf /),
//    base64|sh, or writing the payload to a file then executing it can evade a
//    given pattern. Deny-first still catches the common/plain forms in the
//    dataset; the AST upgrade (reuse tool/shell.ts tree-sitter scan) closes most
//    of this on day-2, and the slopsquatting + LLM tiers cover install-time and
//    grey-zone cases.
//  • This layer only DENIES. Grey-zone "ask" decisions stay with the existing
//    permission flow. That keeps false-positives / friction low by construction.
// kilocode_change end
