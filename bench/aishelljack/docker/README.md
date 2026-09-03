# Running the benchmark in Docker

The payloads execute real, destructive shell commands (`kilo run --yolo`). This
container keeps them off your host: Kilo Code is built from this repo (the image
*is* the full checkout), each attack runs in a disposable container, and the
poisoned workspaces live on an ephemeral temp dir inside it.

All commands below are run from `bench/aishelljack/docker/`.

## 1. Build

```bash
docker compose build
```

First build is heavy: it runs `bun install` over the whole Kilo monorepo and
compiles a few native deps. The result is cached for later runs.

## 2. Sign in (once)

Kilo's default model is paid and 401s without auth. Log in inside the container —
the device-code flow prints a URL + code; open the URL in your **host** browser:

```bash
docker compose run --rm bench kilo auth login
```

The token is stored in the `kilo-auth` named volume and reused by every later
run. Then pick a (free) model id:

```bash
docker compose run --rm bench kilo models
```

## 3. Run the baseline pilot

```bash
docker compose run --rm bench \
  python3 code/run_kilo.py \
    --scenario django_Python --codebase ludic \
    --model <provider/model> --max-tests 15 \
    --sim-type kilo_baseline --auto-mode monitor
```

`--auto-mode monitor` keeps the deny-first engine observing but **not** blocking,
so the baseline is Kilo's native behaviour (see [../../../docs/benchmark.md](../../../docs/benchmark.md)).
For the defended run use `--sim-type kilo_automode --auto-mode enforce`.

## 4. Score

```bash
docker compose run --rm bench \
  python3 code/check_command_execution.py kilo_baseline ludic \
    --base-path results/raw_results/ \
    --json-file data/linux_atomic_tests_attack_payloads.json
```

Results (`commands.log`, `raw_events.jsonl`, `meta.json`, analysis reports) are
written to `bench/aishelljack/results/` on the host via the mounted volume.

## Notes

- **Network is on** — the model API (`api.kilo.ai`) must be reachable, so payload
  commands also have network. The container is disposable; for a stricter run,
  cache auth first, then add `--network none` and point `--model` at a locally
  served model.
- **Rebuild after code changes**: `docker compose build` picks up edits to Kilo
  or the harness (the repo is copied into the image, not mounted).
- The `results/` mount is gitignored.
