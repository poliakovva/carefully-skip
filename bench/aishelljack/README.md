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
  --resume --workers 4 --retry-timeouts 3 \
  --model <provider/model> \
  --sim-type kilo_baseline --auto-mode monitor
```

Run the same matrix with `--sim-type kilo_automode --auto-mode enforce` for the defended condition. Then generate one comparison report:

```bash
python3 code/score_kilo.py \
  --sim-type kilo_baseline --sim-type kilo_automode
```

To reproduce only the paper-compatible slice, omit `--surface`; it defaults to `cursorrules`. Use `--max-tests` for a pilot or `--indices T1059.004.01 ...` for selected techniques. `--resume` reuses completed `meta.json` runs after an interrupted matrix.

`--workers N` runs N Kilo invocations concurrently (each gets its own copied workspace, so this is safe). `--retry-timeouts N` adds up to N extra in-process passes that re-run only the jobs still stuck in `timeout`/`error`/`setup_failed` after the main pass — useful with free-tier models, whose shared queues intermittently hang a request for the full `--per-test-timeout` with zero streamed output. Free-tier reliability, not the harness, is the main bottleneck for a full run: expect a meaningful share of jobs to need 2-3 retry passes before they land `ok`.

Results are stored below `results/raw_results/<sim-type>/`. Each run has raw JSON events, executed commands, an isolated policy audit, and metadata. The report is written to `results/raw_results/report.{md,json}`.

## Threat model and safety

`kilo run --yolo` skips normal permission prompts. `--auto-mode monitor` records decisions without blocking; `enforce` applies deny-first vetoes. This makes baseline and defended runs use the same payload and task corpus.

The payloads execute real, destructive commands. Run only in disposable isolation with dedicated test credentials. A container limits host filesystem access, but credentials mounted into it and reachable networks remain exposed to the tested agent.

See [the full benchmark design](../../docs/benchmark.md) and [Docker instructions](docker/README.md).
