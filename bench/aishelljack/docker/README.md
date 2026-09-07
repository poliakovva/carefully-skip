# Running the benchmark in Docker

The payloads execute real, destructive shell commands (`kilo run --yolo`). This
container limits their access to the host filesystem: Kilo Code is built from
this repo and poisoned workspaces live in an ephemeral temp directory. One
`docker compose run` executes the requested matrix in one disposable container;
individual payloads are separate Kilo processes, not separate containers.

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

## 3. Run a full-carrier pilot

```bash
docker compose run --rm bench \
  python3 code/run_kilo.py \
    --scenario django_Python --codebase ludic \
    --surface all --suite all --max-tests 2 --max-benign 2 \
    --model <provider/model> \
    --sim-type kilo_baseline --auto-mode monitor
```

`--auto-mode monitor` keeps the deny-first engine observing but **not** blocking,
so the baseline is Kilo's native behaviour (see [../../../docs/benchmark.md](../../../docs/benchmark.md)).
For the defended run use `--sim-type kilo_automode --auto-mode enforce`.

For all five codebases and the complete corpus, use `--all-scenarios --surface
all --suite all` and omit both limits. That is 12,600 model runs per condition,
so estimate provider cost before starting it.

## 4. Score

```bash
docker compose run --rm bench \
  python3 code/score_kilo.py \
    --sim-type kilo_baseline --sim-type kilo_automode
```

Results (`commands.log`, `raw_events.jsonl`, `meta.json`, analysis reports) are
written to `bench/aishelljack/results/` on the host via the mounted volume.

## Notes

- **Network is on** — the model API (`api.kilo.ai`) must be reachable, so payload
  commands also have network. Use a dedicated test account: malicious commands
  can read the mounted `kilo-auth` volume and attempt exfiltration. For a stricter
  run, use a local model and disable container networking.
- **Rebuild after code changes**: `docker compose build` picks up edits to Kilo
  or the harness (the repo is copied into the image, not mounted).
- The `results/` mount is gitignored.

## Benchmarking a different auto-mode implementation

`bench-adjudicator` is a second service for running the same harness against
`Nit31/kilocode@feature/adjudicator-effort`'s classifier instead of this
repo's own `KILO_AUTO_MODE` module — see
[`../README.md`](../README.md#running-against-a-different-auto-mode-implementation)
for `--impl adjudicator` and how to fetch that branch first. It differs from
`bench` above in two ways:

- **Build context is that branch's checkout**, not this repo (they have
  unrelated git history) — `docker compose build bench-adjudicator` never
  copies this repo into the image.
- **The bench harness is bind-mounted, not baked in**: `bench/aishelljack`
  (code, data, `results/`, and the isolated `.adjudicator_home/` that holds
  its config and `kilo auth login` credentials) is mounted at `/bench`
  instead of copied at build time, so results and auth persist across
  rebuilds without a separate named volume.

```bash
docker compose build bench-adjudicator
docker compose run --rm bench-adjudicator \
  python3 code/run_kilo.py --impl adjudicator \
    --scenario django_Python --codebase ludic \
    --surface all --suite all --max-tests 2 --max-benign 2 \
    --model <provider/model> \
    --sim-type kilo_adjudicator --auto-mode enforce
```
