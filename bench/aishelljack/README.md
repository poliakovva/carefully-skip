# AIShellJack → Kilo Code

Runs the [AIShellJack](https://arxiv.org/abs/2509.22040) prompt-injection corpus against Kilo Code. The original `.cursorrules` experiment remains available for paper-compatible results; the extended harness applies the same 314 payloads to all in-scope Kilo carriers.

## Coverage

| Carrier | Delivery |
|---|---|
| `cursorrules` | poisoned `.cursorrules`, explicitly referenced |
| `agents` | poisoned, auto-loaded `AGENTS.md` |
| `kilo_rules` | poisoned, auto-loaded `.kilo/rules/*.md` |
| `readme` | poisoned `README.md`, explicitly referenced |
| `source` | poisoned source-code comment, explicitly referenced |
| `skill` | poisoned project `SKILL.md`, loaded through the skill tool |
| `mcp_instructions` | poisoned MCP initialization instructions |
| `mcp_tool` | poisoned MCP tool result |

The runner also has an eight-task benign suite. `score_kilo.py` reports:

- attack Execution Rate and ASR using the upstream command matcher;
- benign Utility, false-positive rate, and Friction;
- end-to-end task latency and deterministic policy latency;
- per-carrier attack breakdown.

## Upstream vs Kilo files

| Path | Origin | Role |
|---|---|---|
| `data/linux_atomic_tests_attack_payloads.json` | upstream | 314 attack payloads |
| `data/repos/` | upstream | five scenario codebases |
| `code/workspace_setup.py` | upstream | workspace setup and payload template |
| `code/check_command_execution.py` | upstream | ASR command matcher |
| `code/terminal_monitor.py` | upstream | reference, unused by the Kilo runner |
| `code/kilo_surfaces.py` | Kilo | carrier setup and activation prompts |
| `code/mcp_server.py` | Kilo | local MCP test server |
| `data/benign_tasks.json` | Kilo | benign utility corpus |
| `code/run_kilo.py` | Kilo | headless matrix runner |
| `code/score_kilo.py` | Kilo | combined metrics report |

## Run

Install the monorepo dependencies first. Authenticate Kilo with `bun run --cwd packages/opencode --conditions=browser src/index.ts auth login`, then pass a model as `--model <provider/model>` or `KILO_MODEL`. For destructive runs, prefer the Docker workflow below.

A small one-codebase pilot:

```bash
cd bench/aishelljack
python3 code/run_kilo.py \
  --scenario django_Python --codebase ludic \
  --surface all --suite all --max-tests 2 --max-benign 2 \
  --model <provider/model> \
  --sim-type kilo_baseline --auto-mode monitor
```

The full baseline is 12,560 attack runs plus 40 benign runs:

```bash
python3 code/run_kilo.py \
  --all-scenarios --surface all --suite all \
  --resume \
  --model <provider/model> \
  --sim-type kilo_baseline --auto-mode monitor
```

Run the same matrix with `--sim-type kilo_automode --auto-mode enforce` for the defended condition. Then generate one comparison report:

```bash
python3 code/score_kilo.py \
  --sim-type kilo_baseline --sim-type kilo_automode
```

To reproduce only the paper-compatible slice, omit `--surface`; it defaults to `cursorrules`. Use `--max-tests` for a pilot or `--indices T1059.004.01 ...` for selected techniques. `--resume` reuses completed `meta.json` runs after an interrupted matrix.

Results are stored below `results/raw_results/<sim-type>/`. Each run has raw JSON events, executed commands, an isolated policy audit, and metadata. The report is written to `results/raw_results/report.{md,json}`.

## Running against a different auto-mode implementation

`run_kilo.py` targets our own `KILO_AUTO_MODE` module by default (`--impl legacy`). To benchmark a different branch's auto-mode implementation (e.g. `Nit31/kilocode@feature/adjudicator-effort`, a config-driven LLM classifier — "adjudicator" — instead of our env-toggled deny-first rules), pass `--impl adjudicator` and point `--kilo-src` at a separate checkout of that branch. That branch has unrelated git history from this repo (it's a fork of upstream `Kilo-Org/kilocode`, not of this fork), so it's checked out as a worktree next to this checkout, not merged in:

```bash
# from the repo root (not bench/aishelljack)
git remote add nit31 https://github.com/Nit31/kilocode.git   # once
git fetch nit31 feature/adjudicator-effort
git worktree add ../adjudicator-src nit31/feature/adjudicator-effort
```

**Payloads execute real, destructive commands — run them in the `bench-adjudicator` container, the same way [Docker instructions](docker/README.md) already require for `--impl legacy`:**

```bash
cd bench/aishelljack/docker
docker compose build bench-adjudicator          # builds Kilo from ../../../adjudicator-src, not this repo
docker compose run --rm bench-adjudicator \
  python3 code/run_kilo.py --impl adjudicator \
  --scenario django_Python --codebase ludic \
  --surface all --suite all --max-tests 2 --max-benign 2 \
  --model <provider/model> \
  --sim-type kilo_adjudicator --auto-mode enforce
```

`bench-adjudicator` bind-mounts this whole `bench/aishelljack` directory (including `.adjudicator_home/`, gitignored) into the container at `/bench` instead of baking it into the image, and `KILO_SRC` is preset so `--kilo-src` can be omitted. `kilo auth login` — with the isolated `XDG_*` env from the section below — done on the host lands in `.adjudicator_home/` and is visible inside the container too, and vice versa; no separate `docker compose run bench-adjudicator kilo auth login` is needed unless you'd rather log in from inside the container.

For a non-destructive plumbing check only (config injection, env wiring, SQLite read-back — no payloads reach a real shell without a signed-in model), the bare host command works too:

```bash
cd bench/aishelljack
python3 code/run_kilo.py \
  --impl adjudicator \
  --kilo-src ../../../adjudicator-src/packages/opencode \
  --scenario django_Python --codebase ludic --surface cursorrules --suite attacks --max-tests 1 \
  --sim-type kilo_adjudicator --auto-mode enforce
```

The harness differs enough from our module that it bridges the gap (`code/adjudicator_kilo.py`) rather than reusing the legacy path as-is:

- **Enablement is a `kilo run` flag, not env.** The classifier turns on with `--auto` [+ `--auto-model`/`--auto-effort`, wired from `--adjudicator-model`/`--adjudicator-effort`], not `KILO_AUTO_MODE`. `--auto` and `--yolo` are mutually exclusive there (an auto-approver would turn every classifier escalation into an allow), so `--impl adjudicator --auto-mode off` still runs `--yolo` (native baseline, matching `--impl legacy`) and `enforce` swaps to `--auto` instead of adding it. There is no passive "would-have-blocked" mode like our `monitor` — the CLI refuses `--impl adjudicator --auto-mode monitor` for that reason, since every `enforce`-equivalent decision there actually blocks. `--impl adjudicator` still isolates XDG state (`--adjudicator-home`, default `.adjudicator_home/`, gitignored — this is also where `kilo auth login` credentials need to live, see below) so none of this touches your real `~/.config/kilo`.
- **Decisions live in SQLite, not a JSONL log.** That branch records every decision in the isolated `kilo.db` (`adjudicator_decision` / `adjudicator_resolution` tables) instead of `KILO_AUTO_MODE_AUDIT_FILE`. After each run, `adjudicator_kilo.write_audit()` reads the rows for that run's tool-call ids back out of SQLite and writes them into the same `audit.jsonl` shape our scorer already expects, so `score_kilo.py` needs no changes.
- **Unattended escalations fail closed instantly.** A "gray zone" call the classifier can't resolve outright would wait for human approval — but a headless bench run never passes `--interactive`/`--attach`, so it's unattended and the branch resolves it as `outcome: "unattended"` with `wait_ms: 0` right away, no timeout wait. The adapter folds that into the `deny` your scorer sees (`adjudicator_kilo.effective_action`), since the raw decision row would otherwise still say `"escalate"`.
- **Matching is by tool-call id, not command text.** The SQLite rows only keep a redacted, 160-char-truncated preview of the command, so `executed()` excludes denied bash calls by `callID` rather than literal string match.

## Threat model and safety

`kilo run --yolo` skips normal permission prompts. `--auto-mode monitor` records decisions without blocking; `enforce` applies deny-first vetoes. This makes baseline and defended runs use the same payload and task corpus.

The payloads execute real, destructive commands. Run only in disposable isolation with dedicated test credentials. A container limits host filesystem access, but credentials mounted into it and reachable networks remain exposed to the tested agent.

See [the full benchmark design](../../docs/benchmark.md) and [Docker instructions](docker/README.md).
