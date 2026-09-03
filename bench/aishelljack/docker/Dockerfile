# AIShellJack → Kilo Code, containerised.
#
# The build context is the repo root: `carefully-skip` is a full Kilo Code
# checkout (kilocode + auto-mode) plus the benchmark, so the image builds Kilo
# from source (linux-native `bun install` — macOS node_modules can't be reused)
# and runs the whole benchmark inside the container. Payloads execute with
# `--yolo`, so keeping them off the host is the point.
FROM oven/bun:1-debian

# python3 runs the harness/scorer; build tools cover any native deps (node-pty,
# sqlite) that `bun install` may compile; git/rg are used by Kilo at runtime.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 git ca-certificates ripgrep build-essential pkg-config \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /kilo
COPY . /kilo

# Install the monorepo deps. Frozen first; fall back if the lockfile drifted.
RUN bun install --frozen-lockfile || bun install

# `kilo <args>` convenience wrapper (auth login, models, …).
RUN printf '#!/usr/bin/env bash\nexec bun run --conditions=browser /kilo/packages/opencode/src/index.ts "$@"\n' \
      > /usr/local/bin/kilo \
 && chmod +x /usr/local/bin/kilo

ENV KILO_SRC=/kilo/packages/opencode \
    KILO_AUTO_MODE=monitor \
    HOME=/root

WORKDIR /kilo/bench/aishelljack
CMD ["python3", "code/run_kilo.py", "--help"]
