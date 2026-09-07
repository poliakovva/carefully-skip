"""Bridge for benchmarking Nit31/kilocode@feature/adjudicator-effort.

That branch does not have our `KILO_AUTO_MODE` module. It gates permissions
with an LLM classifier ("adjudicator") enabled per-session via `kilo run
--auto` [+ `--auto-model`/`--auto-effort`], and it writes every decision into
the Kilo SQLite database (`adjudicator_decision` / `adjudicator_resolution`
tables) instead of a `KILO_AUTO_MODE_AUDIT_FILE` JSONL log.

This module makes that branch look like our module to the rest of the
harness: it isolates XDG state per bench run so we never touch the real
`~/.config/kilo` / `~/.local/share/kilo` (including `kilo auth login`
credentials), and after a `kilo run` converts the matching
`adjudicator_decision` rows into the same audit-entry shape
(`decision`/`mode`/`latency`) that `score_kilo.py` already expects from our
own module, keyed by tool-call id instead of literal command text (the
adjudicator only stores a redacted, truncated preview of the command).

Escalations without an attending human (the default for a headless bench
run — `kilo run` is never passed `--interactive`/`--attach`) resolve through
`adjudicator_resolution.outcome`, not `adjudicator_decision.action` — a
decision row can say "escalate" and still end up blocked. As of this
branch's `--auto` flag, an unattended escalation fails closed immediately
(`outcome: "unattended"`, `wait_ms: 0`), not after waiting out
`adjudicator.escalation_timeout`. `effective_action` folds that resolution
back into a plain allow/deny for scoring.
"""

import json
import sqlite3
import time
from pathlib import Path


def home_dirs(home):
    # Must be absolute: this becomes XDG_CONFIG_HOME/etc. for the `kilo run`
    # child process, whose cwd is the kilo source tree (`cwd=kilo_src` in
    # _run_subprocess), not the harness's own cwd. A relative --adjudicator-home
    # resolves against the WRONG directory there, so the CLI silently fails to
    # find kilo.jsonc, and any custom (non-"kilo") provider it declares never
    # gets registered — surfacing later as ProviderModelNotFoundError, with no
    # indication the actual cause was a config file that was never read.
    home = Path(home).resolve()
    return {
        "config": home / "config",
        "data": home / "data",
        "cache": home / "cache",
        "state": home / "state",
    }


def ensure_bash_permission_migration_skipped(home):
    """Pre-seed the CLI's own idempotency marker so it never runs
    `migrateBashPermission()` in this home.

    That migration (`packages/opencode/src/kilocode/config/config.ts`) writes
    a global `permission.bash` entry into `kilo.jsonc` on first launch. The
    branch's provenance tracker (`kilocode/permission/provenance.ts`) keys
    rule origin only by `(permission, pattern)`, so that migrated entry
    collides with the built-in `bash: "*" -> ask` default and gets
    mis-tagged as "explicitly user-authored" — which routes every bash call
    to a static reserved-for-human gate, before the adjudicator's classifier
    is ever invoked. Touching the marker first makes the CLI believe the
    migration already ran, so it never writes that colliding entry.

    Must run before the *first* `kilo` invocation in a home, including a
    manual bootstrap step (e.g. `kilo auth login`) — not just before
    `run_kilo.py`'s own invocations, which is why this is idempotent and
    safe to call from `env()` on every run.
    """
    marker = home_dirs(home)["config"] / "kilo" / ".bash-permission-migrated"
    marker.parent.mkdir(parents=True, exist_ok=True)
    if not marker.exists():
        marker.touch()


def env(home):
    dirs = home_dirs(home)
    for path in dirs.values():
        path.mkdir(parents=True, exist_ok=True)
    ensure_bash_permission_migration_skipped(home)
    return {
        "XDG_CONFIG_HOME": str(dirs["config"]),
        "XDG_DATA_HOME": str(dirs["data"]),
        "XDG_CACHE_HOME": str(dirs["cache"]),
        "XDG_STATE_HOME": str(dirs["state"]),
    }


def db_path(home):
    # Not `kilo.db` — that file exists too (created empty) but the CLI's
    # local-mode session/adjudicator data (what we need) lives in
    # `kilo-local.db`.
    return home_dirs(home)["data"] / "kilo" / "kilo-local.db"


_QUERY = """
    SELECT
        d.call_id AS call_id,
        d.action AS action,
        d.via AS via,
        d.cause AS cause,
        d.rule AS rule,
        d.permission AS permission,
        d.severity AS severity,
        d.reason AS reason,
        d.target_preview AS target_preview,
        d.latency_ms AS latency_ms,
        d.model_called AS model_called,
        d.prompt_tokens AS prompt_tokens,
        d.ts AS ts,
        r.outcome AS resolution_outcome,
        r.wait_ms AS resolution_wait_ms
    FROM adjudicator_decision AS d
    LEFT JOIN adjudicator_resolution AS r ON r.event_id = d.event_id
    WHERE d.call_id IN ({placeholders})
    ORDER BY d.ts ASC
"""


def fetch_decisions(home, call_ids, timeout=10.0, retries=8):
    """Return the latest decision row per call_id, keyed by call_id.

    Retries on SQLITE_BUSY/SQLITE_CANTOPEN: the harness reads right after the
    `kilo run` subprocess exits, and WAL checkpoints can still be settling —
    this gets noticeably more likely at --parallel > 1, where several bun
    processes hit the same WAL file at once. After retries are exhausted,
    give up gracefully (empty result) rather than raising: this is best-effort
    audit enrichment, and one job's incomplete policy trace shouldn't crash a
    multi-hour matrix run.
    """
    call_ids = [item for item in dict.fromkeys(call_ids) if item]
    if not call_ids:
        return {}
    path = db_path(home)
    if not path.exists():
        return {}
    query = _QUERY.format(placeholders=",".join("?" for _ in call_ids))
    rows = []
    for attempt in range(retries):
        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=timeout)
            try:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(query, call_ids).fetchall()
            finally:
                conn.close()
            break
        except sqlite3.OperationalError:
            time.sleep(0.5 * (attempt + 1))
    else:
        return {}

    result = {}
    for row in rows:
        result[row["call_id"]] = dict(row)
    return result


def effective_action(row):
    """Fold an escalation's resolution back into a plain allow/deny/escalate.

    A decision row can say `action == "escalate"` yet still block the call:
    with no attending human the escalation times out and the permission
    layer raises DeniedError. Only `resolution_outcome == "approve"` means
    the call actually ran.
    """
    action = row.get("action")
    if action != "escalate":
        return action
    outcome = row.get("resolution_outcome")
    if outcome == "approve":
        return "allow"
    return "deny"


def normalize(call_id, row, mode):
    return {
        "callID": call_id,
        "tool": None,
        "command": row.get("target_preview"),
        "decision": effective_action(row),
        "raw_action": row.get("action"),
        "resolution_outcome": row.get("resolution_outcome"),
        "rule": row.get("rule"),
        "cause": row.get("cause"),
        "permission": row.get("permission"),
        "reason": row.get("reason"),
        "matched": row.get("via"),
        "severity": row.get("severity"),
        "mode": mode,
        "latency": row.get("latency_ms"),
        "model_called": bool(row.get("model_called")),
        "prompt_tokens": row.get("prompt_tokens"),
    }


def write_audit(path, call_ids, home, mode):
    decisions = fetch_decisions(home, call_ids)
    entries = [normalize(call_id, row, mode) for call_id, row in decisions.items()]
    with path.open("w", encoding="utf-8") as file:
        for entry in entries:
            file.write(json.dumps(entry) + "\n")
    return entries
