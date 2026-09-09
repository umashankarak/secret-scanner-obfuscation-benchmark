#!/usr/bin/env python3
"""
aggregate_seeds.py -- summarize results across independently generated corpora.

Reads, from each seed directory produced by run_multiseed.sh:
  results/normalized_robustness.csv      (per run x family retention)
  results/robustness_index_variants.csv  (RI under alternative aggregations)
  results/by_transformation.csv          (per run x transformation retention)
  results/run_timing.json                (wall-clock per configuration)
and writes mean / SD / min / max across seeds for each quantity:
  multiseed_family.csv, multiseed_ri.csv, multiseed_transformation.csv,
  multiseed_timing.csv, plus a console table.

Bootstrap CIs (analyze.py) capture sampling variance within one corpus; the
across-seed SD here captures corpus-generation variance. Both are reported.

Usage:
  python aggregate_seeds.py --seeds out/seed_* --out out/multiseed
"""
from __future__ import annotations

import argparse
import csv
import json
import math
from collections import defaultdict
from pathlib import Path


def stats(xs):
    xs = [float(x) for x in xs]
    n = len(xs)
    m = sum(xs) / n
    sd = math.sqrt(sum((x - m) ** 2 for x in xs) / (n - 1)) if n > 1 else 0.0
    return n, m, sd, min(xs), max(xs)


def collect(seed_dirs, rel, key_fields, value_field):
    acc = defaultdict(list)
    for d in seed_dirs:
        fp = Path(d) / "results" / rel
        if not fp.exists():
            print(f"[warn] missing {fp}")
            continue
        with fp.open(newline="") as fh:
            for r in csv.DictReader(fh):
                if r.get(value_field, "") == "":
                    continue
                acc[tuple(r[k] for k in key_fields)].append(r[value_field])
    return acc


def write(acc, key_fields, out: Path, name):
    with (out / name).open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(list(key_fields) + ["n_seeds", "mean", "sd", "min", "max"])
        for k in sorted(acc):
            n, m, sd, lo, hi = stats(acc[k])
            w.writerow(list(k) + [n, f"{m:.4f}", f"{sd:.4f}", f"{lo:.4f}", f"{hi:.4f}"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", nargs="+", required=True, help="seed directories")
    ap.add_argument("--out", default="out/multiseed")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    seeds = [d for d in a.seeds if Path(d).is_dir()]

    fam = collect(seeds, "normalized_robustness.csv", ["run", "family"], "retention")
    write(fam, ["run", "family"], out, "multiseed_family.csv")
    ri = collect(seeds, "robustness_index_variants.csv", ["run", "variant"], "value")
    write(ri, ["run", "variant"], out, "multiseed_ri.csv")
    tr = collect(seeds, "by_transformation.csv", ["run", "transformation_id", "family"], "retention")
    write(tr, ["run", "transformation_id", "family"], out, "multiseed_transformation.csv")

    timing = defaultdict(list)
    for d in seeds:
        fp = Path(d) / "results" / "run_timing.json"
        if fp.exists():
            for run, v in json.loads(fp.read_text()).items():
                timing[(run,)].append(v["wall_seconds"])
    write(timing, ["run"], out, "multiseed_timing.csv")

    runs = sorted({k[0] for k in fam})
    fams = sorted({k[1] for k in fam})
    print(f"\n=== Retention across {len(seeds)} seeds: mean +/- SD (percentage points) ===")
    print("family".ljust(16) + "".join(r.rjust(22) for r in runs))
    for f in fams:
        cells = []
        for r in runs:
            n, m, sd, lo, hi = stats(fam[(r, f)])
            cells.append(f"{100*m:5.1f} +/- {100*sd:4.1f}".rjust(22))
        print(f.ljust(16) + "".join(cells))
    print("\n=== Robustness index variants across seeds ===")
    for k in sorted(ri):
        n, m, sd, lo, hi = stats(ri[k])
        print(f"  {k[0]:22s} {k[1]:32s} {100*m:5.1f} +/- {100*sd:4.1f}  [{100*lo:5.1f}, {100*hi:5.1f}]")
    if timing:
        print("\n=== Wall-clock scan time per configuration (s) ===")
        for k in sorted(timing):
            n, m, sd, lo, hi = stats(timing[k])
            print(f"  {k[0]:22s} {m:8.1f} +/- {sd:5.1f}")
    print(f"\nWrote multiseed_*.csv to {out}/")


if __name__ == "__main__":
    main()
