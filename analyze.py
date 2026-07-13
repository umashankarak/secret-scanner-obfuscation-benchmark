#!/usr/bin/env python3
"""
analyze.py -- ceiling-normalized robustness from a harness detection_matrix.csv
==============================================================================
Raw detection rate penalizes a scanner for secret types it cannot detect even
in PLAINTEXT. TruffleHog, for example, is detector-specific and has no generic
high-entropy catch-all, so it never fires on the generic_hex_token type at all;
Gitleaks misses the bare AWS *secret* key because it has no distinctive prefix.
Those are detector-coverage gaps, not obfuscation failures.

This script normalizes each scanner against its OWN plaintext (control) ceiling,
per secret type, so the numbers measure robustness to obfuscation instead of
baseline coverage. Rule: never count a scanner as 'evaded' on a type it can't
detect in plaintext.

Per (run, family):
  raw           mean detection over all rows (what the harness prints)
  covered_only  mean detection restricted to types the scanner detects in
                plaintext (ceiling > 0)
  retention     mean over covered types of (family_detection / ceiling)
                = 'of the secrets it can find in plaintext, what fraction
                   survived this obfuscation'   <-- the robustness measure

Usage:
  python analyze.py --matrix results/detection_matrix.csv --out results
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Dict, List, Tuple

META = ["id", "secret_type", "transformation_id", "family", "depth", "carrier"]
CONTROL_FAMILY = "control"


def load(matrix_path: str) -> Tuple[List[dict], List[str]]:
    rows: List[dict] = []
    with open(matrix_path, newline="") as fh:
        r = csv.DictReader(fh)
        run_keys = [c for c in r.fieldnames if c not in META]
        for d in r:
            for k in run_keys:
                d[k] = int(d[k])
            rows.append(d)
    return rows, run_keys


def mean(xs) -> float:
    xs = list(xs)
    return sum(xs) / len(xs) if xs else 0.0


def ceilings(rows: List[dict], run_keys: List[str]) -> Tuple[Dict[str, Dict[str, float]], List[str]]:
    """ceiling[run][type] = plaintext (control-family) detection rate for that type."""
    types = sorted({r["secret_type"] for r in rows})
    out: Dict[str, Dict[str, float]] = {}
    for run in run_keys:
        out[run] = {}
        for t in types:
            ctrl = [r[run] for r in rows
                    if r["secret_type"] == t and r["family"] == CONTROL_FAMILY]
            out[run][t] = mean(ctrl)
    return out, types


def analyze(rows: List[dict], run_keys: List[str]):
    ceil, types = ceilings(rows, run_keys)
    families = sorted({r["family"] for r in rows})
    result = {"by_family": {}, "coverage": {}, "robustness_index": {}}

    for run in run_keys:
        covered = [t for t in types if ceil[run][t] > 0]
        uncovered = [t for t in types if ceil[run][t] == 0]
        result["coverage"][run] = {
            "covered": covered,
            "uncovered": uncovered,
            "ceilings": {t: round(ceil[run][t], 4) for t in types},
        }
        result["by_family"][run] = {}
        for fam in families:
            fam_rows = [r for r in rows if r["family"] == fam]
            raw = mean(r[run] for r in fam_rows)
            covered_only = mean(r[run] for r in fam_rows if r["secret_type"] in covered)
            rets = []
            for t in covered:
                fam_t = [r[run] for r in fam_rows if r["secret_type"] == t]
                if fam_t:
                    # Clamp per-type retention at 1.0: "fraction of plaintext-detectable
                    # surviving obfuscation" cannot exceed the plaintext ceiling. Uncapped
                    # ratios slightly exceed 1.0 for a few types (decode surfacing a
                    # sub-threshold plaintext secret, plus per-type sampling variance).
                    rets.append(min(mean(fam_t) / ceil[run][t], 1.0))
            result["by_family"][run][fam] = {
                "raw": raw, "covered_only": covered_only, "retention": mean(rets),
            }
        obf = [f for f in families if f != CONTROL_FAMILY]
        result["robustness_index"][run] = mean(
            result["by_family"][run][f]["retention"] for f in obf)

    return result, families, types


def pct(x: float) -> str:
    return f"{100 * x:5.1f}%"


def report(result, run_keys, families, out: str):
    outp = Path(out)
    outp.mkdir(parents=True, exist_ok=True)
    w = max(len(k) for k in run_keys)

    print("\n=== Ceiling-normalized RETENTION by family (robustness) ===")
    print("of the secrets each scanner detects in plaintext, the fraction surviving obfuscation")
    print("family".ljust(16) + "".join(k.rjust(w + 2) for k in run_keys))
    for fam in families:
        print(fam.ljust(16) + "".join(
            pct(result["by_family"][k][fam]["retention"]).rjust(w + 2) for k in run_keys))
    print("robustness_idx".ljust(16) + "".join(
        pct(result["robustness_index"][k]).rjust(w + 2) for k in run_keys))

    print("\n=== Detector coverage (types with plaintext ceiling > 0) ===")
    for k in run_keys:
        cov = result["coverage"][k]
        missing = ", ".join(cov["uncovered"]) if cov["uncovered"] else "none"
        print(f"  {k}: covers {len(cov['covered'])}/{len(cov['covered']) + len(cov['uncovered'])} types"
              f"  |  no plaintext detection for: {missing}")

    with (outp / "normalized_robustness.csv").open("w", newline="") as fh:
        wr = csv.writer(fh)
        wr.writerow(["run", "family", "raw", "covered_only", "retention"])
        for k in run_keys:
            for fam in families:
                m = result["by_family"][k][fam]
                wr.writerow([k, fam, f"{m['raw']:.4f}",
                             f"{m['covered_only']:.4f}", f"{m['retention']:.4f}"])
    (outp / "coverage.json").write_text(json.dumps(result["coverage"], indent=2))
    print(f"\nWrote normalized_robustness.csv and coverage.json to {outp}/")


def main():
    ap = argparse.ArgumentParser(description="Ceiling-normalized robustness analysis")
    ap.add_argument("--matrix", required=True, help="path to detection_matrix.csv")
    ap.add_argument("--out", default="results")
    args = ap.parse_args()
    rows, run_keys = load(args.matrix)
    result, families, types = analyze(rows, run_keys)
    report(result, run_keys, families, args.out)


if __name__ == "__main__":
    main()
