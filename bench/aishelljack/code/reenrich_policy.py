#!/usr/bin/env python3
"""Retroactively re-enrich already-collected `meta.json` policy entries.

The `kilo_adjudicator_ds_instant`/`kilo_adjudicator_ds_thinking` runs
predate the `cause`/`permission` fields added to
`adjudicator_kilo.normalize()`. Their `kilo-local.db` files are still on
disk, untouched, and every `meta.json`'s `policy` entries already carry the
`callID` needed to re-derive a fresh, fully-enriched entry from that same
database. This rewrites `policy` in place from that authoritative source —
it re-derives, it does not fabricate, and it never runs `kilo` again.
"""

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BENCH = HERE.parent
sys.path.insert(0, str(HERE))
import adjudicator_kilo  # noqa: E402

LABEL_HOMES = {
    "kilo_adjudicator_ds_instant": BENCH / ".adjudicator_home_instant",
    "kilo_adjudicator_ds_thinking": BENCH / ".adjudicator_home_thinking",
}


def reenrich_label(label, home, results_root):
    root = results_root / label
    if not root.exists():
        print(f"skip {label}: {root} not found")
        return
    files = list(root.rglob("meta.json"))
    call_ids = set()
    for path in files:
        item = json.loads(path.read_text(encoding="utf-8"))
        for entry in item.get("policy", []):
            if isinstance(entry, dict) and entry.get("callID"):
                call_ids.add(entry["callID"])

    decisions = adjudicator_kilo.fetch_decisions(home, call_ids)
    print(f"{label}: {len(decisions)}/{len(call_ids)} call_ids resolved from {home}")

    updated = 0
    for path in files:
        item = json.loads(path.read_text(encoding="utf-8"))
        default_mode = item.get("auto_mode")
        policy = item.get("policy", [])
        new_policy = []
        changed = False
        for entry in policy:
            call_id = entry.get("callID") if isinstance(entry, dict) else None
            row = decisions.get(call_id) if call_id else None
            if row is None:
                new_policy.append(entry)
                continue
            mode = entry.get("mode") or default_mode
            new_policy.append(adjudicator_kilo.normalize(call_id, row, mode))
            changed = True
        if changed:
            item["policy"] = new_policy
            path.write_text(json.dumps(item, indent=2) + "\n", encoding="utf-8")
            updated += 1
    print(f"{label}: rewrote policy in {updated}/{len(files)} meta.json files")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", default=BENCH / "results" / "raw_results", type=Path)
    parser.add_argument("--label", action="append", help="restrict to these labels (default: all known)")
    args = parser.parse_args()

    for label in args.label or list(LABEL_HOMES):
        home = LABEL_HOMES.get(label)
        if home is None:
            print(f"skip {label}: no known adjudicator-home mapping")
            continue
        reenrich_label(label, home, args.results)


if __name__ == "__main__":
    main()
