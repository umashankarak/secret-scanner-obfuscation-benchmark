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

Extended outputs (added for the revision; all derived from the same matrix):
  retention_ci.csv            family retention + robustness index with bootstrap 95% CIs
  robustness_index_variants.csv  RI under alternative aggregations (sensitivity analysis)
  by_transformation.csv       per-transformation raw rate and retention (23 x runs) + CIs
  by_carrier.csv              family retention per carrier (ceiling computed per type+carrier)
  by_type.csv                 per-credential-type family detection and retention ratio
  ceilings.csv                per-type plaintext ceilings with n, so they can be audited
  raw_rates.csv               raw (un-normalized) detection rate by family

Usage:
  python analyze.py --matrix results/detection_matrix.csv --out results
  python analyze.py --matrix ... --out ... --boot 2000 --seed 7 --min-ceiling 0.5
"""

from __future__ import annotations

import argparse
import csv
import json
import random
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


# ----------------------------------------------------------------------------
# Extended analysis (revision): CIs, RI sensitivity, per-transformation /
# per-carrier / per-type breakdowns, auditable ceilings, raw rates.
# ----------------------------------------------------------------------------

def _cells(rows, run, key_fields):
    """Aggregate detection outcomes into (n, k) per cell keyed by key_fields."""
    cells: Dict[tuple, list] = {}
    for r in rows:
        k = tuple(r[f] for f in key_fields)
        c = cells.setdefault(k, [0, 0])
        c[0] += 1
        c[1] += r[run]
    return cells


def _retention_from_cells(fam_cells, ceil_cells, types, families, min_ceiling):
    """fam_cells[(family,type)] = [n,k]; ceil_cells[type] = [n,k].
    Returns ({family: retention}, covered_types)."""
    ceil = {t: (ceil_cells[t][1] / ceil_cells[t][0]) if ceil_cells.get(t, [0, 0])[0] else 0.0
            for t in types}
    covered = [t for t in types if ceil[t] > 0 and ceil[t] >= min_ceiling]
    ret = {}
    for fam in families:
        vals = []
        for t in covered:
            c = fam_cells.get((fam, t))
            if c and c[0]:
                vals.append(min((c[1] / c[0]) / ceil[t], 1.0))
        ret[fam] = mean(vals)
    return ret, covered


def _ri_variants(ret, fam_n, families):
    """Robustness-index variants from per-family retention and family sizes."""
    obf = [f for f in families if f != CONTROL_FAMILY]
    obf_nc = [f for f in obf if f != "contextual"]
    def unweighted(fs): return mean(ret[f] for f in fs)
    def weighted(fs):
        tot = sum(fam_n[f] for f in fs)
        return sum(ret[f] * fam_n[f] for f in fs) / tot if tot else 0.0
    return {
        "unweighted": unweighted(obf),
        "unweighted_excl_contextual": unweighted(obf_nc),
        "sample_weighted": weighted(obf),
        "sample_weighted_excl_contextual": weighted(obf_nc),
    }


def _resample_cells(cells, rng):
    """Stratified bootstrap: within every cell redraw k ~ Binomial(n, k/n).
    Equivalent to resampling the n samples of that cell with replacement."""
    out = {}
    for key, (n, k) in cells.items():
        p = k / n if n else 0.0
        kk = sum(1 for _ in range(n) if rng.random() < p) if 0 < p < 1 else k
        out[key] = [n, kk]
    return out


def _pct_ci(vals, lo=2.5, hi=97.5):
    s = sorted(vals)
    if not s:
        return (0.0, 0.0)
    def q(p):
        i = (len(s) - 1) * p / 100.0
        f = int(i); c = min(f + 1, len(s) - 1)
        return s[f] + (s[c] - s[f]) * (i - f)
    return (q(lo), q(hi))


def extended_analysis(rows, run_keys, families, types, out: str,
                      boot: int = 2000, seed: int = 7, min_ceiling: float = 0.0):
    outp = Path(out)
    rng = random.Random(seed)
    obf = [f for f in families if f != CONTROL_FAMILY]
    fam_n = {f: sum(1 for r in rows if r["family"] == f) for f in families}
    trans = sorted({(r["transformation_id"], r["family"]) for r in rows})
    carriers = sorted({r["carrier"] for r in rows})
    ci_rows, var_rows, tr_rows = [], [], []

    print("\n=== Bootstrap 95% CIs (stratified by type x transformation x carrier, "
          f"B={boot}) ===")
    for run in run_keys:
        # base cells at finest granularity, so resampling respects the design
        fine = _cells(rows, run, ["family", "secret_type", "transformation_id", "carrier"])

        def collapse(fine_cells):
            fam_c, ceil_c, tr_c = {}, {}, {}
            for (fam, t, tid, car), (n, k) in fine_cells.items():
                a = fam_c.setdefault((fam, t), [0, 0]); a[0] += n; a[1] += k
                b = tr_c.setdefault((tid, t), [0, 0]); b[0] += n; b[1] += k
                if fam == CONTROL_FAMILY:
                    c = ceil_c.setdefault(t, [0, 0]); c[0] += n; c[1] += k
            return fam_c, ceil_c, tr_c

        def tr_retention(tr_c, ceil_c):
            ceil = {t: ceil_c[t][1] / ceil_c[t][0] for t in types if ceil_c.get(t, [0])[0]}
            cov = [t for t in types if ceil.get(t, 0) > 0 and ceil[t] >= min_ceiling]
            out = {}
            for tid, _fam in trans:
                vals = [min((tr_c[(tid, t)][1] / tr_c[(tid, t)][0]) / ceil[t], 1.0)
                        for t in cov if (tid, t) in tr_c and tr_c[(tid, t)][0]]
                out[tid] = mean(vals)
            return out

        fam_c, ceil_c, tr_c = collapse(fine)
        ret, covered = _retention_from_cells(fam_c, ceil_c, types, families, min_ceiling)
        ri = _ri_variants(ret, fam_n, families)
        trret = tr_retention(tr_c, ceil_c)

        boots_fam = {f: [] for f in families}
        boots_ri = {k: [] for k in ri}
        boots_tr = {tid: [] for tid, _ in trans}
        for _ in range(boot):
            bf, bc, bt = collapse(_resample_cells(fine, rng))
            bret, _cov = _retention_from_cells(bf, bc, types, families, min_ceiling)
            for f in families:
                boots_fam[f].append(bret[f])
            for k, v in _ri_variants(bret, fam_n, families).items():
                boots_ri[k].append(v)
            for tid, v in tr_retention(bt, bc).items():
                boots_tr[tid].append(v)

        print(f"\n  {run}  (covered types: {len(covered)}/{len(types)})")
        for f in families:
            lo, hi = _pct_ci(boots_fam[f])
            ci_rows.append([run, f, fam_n[f], f"{ret[f]:.4f}", f"{lo:.4f}", f"{hi:.4f}"])
            print(f"    {f:16s} {pct(ret[f])}  [{pct(lo)}, {pct(hi)}]")
        for k in ri:
            lo, hi = _pct_ci(boots_ri[k])
            var_rows.append([run, k, f"{ri[k]:.4f}", f"{lo:.4f}", f"{hi:.4f}"])
            print(f"    RI {k:32s} {pct(ri[k])}  [{pct(lo)}, {pct(hi)}]")
        for tid, fam in trans:
            n = sum(1 for r in rows if r["transformation_id"] == tid)
            raw = mean(r[run] for r in rows if r["transformation_id"] == tid)
            lo, hi = _pct_ci(boots_tr[tid])
            tr_rows.append([run, tid, fam, n, f"{raw:.4f}", f"{trret[tid]:.4f}",
                            f"{lo:.4f}", f"{hi:.4f}"])

    with (outp / "retention_ci.csv").open("w", newline="") as fh:
        wr = csv.writer(fh)
        wr.writerow(["run", "family", "n_samples", "retention", "ci95_lo", "ci95_hi"])
        wr.writerows(ci_rows)
    with (outp / "robustness_index_variants.csv").open("w", newline="") as fh:
        wr = csv.writer(fh)
        wr.writerow(["run", "variant", "value", "ci95_lo", "ci95_hi"])
        wr.writerows(var_rows)
    with (outp / "by_transformation.csv").open("w", newline="") as fh:
        wr = csv.writer(fh)
        wr.writerow(["run", "transformation_id", "family", "n_samples", "raw_rate",
                     "retention", "ci95_lo", "ci95_hi"])
        wr.writerows(tr_rows)

    # ---- per-carrier retention: ceiling computed per (type, carrier) ----
    with (outp / "by_carrier.csv").open("w", newline="") as fh:
        wr = csv.writer(fh)
        wr.writerow(["run", "carrier", "family", "n_samples", "raw_rate", "retention"])
        for run in run_keys:
            for car in carriers:
                sub = [r for r in rows if r["carrier"] == car]
                fam_c = _cells(sub, run, ["family", "secret_type"])
                ceil_c = {t: v for (f, t), v in fam_c.items() if f == CONTROL_FAMILY}
                ret, _ = _retention_from_cells(fam_c, ceil_c, types, families, min_ceiling)
                for f in families:
                    fr = [r[run] for r in sub if r["family"] == f]
                    if fr:
                        wr.writerow([run, car, f, len(fr), f"{mean(fr):.4f}", f"{ret[f]:.4f}"])

    # ---- per-type detection and retention ratio ----
    with (outp / "by_type.csv").open("w", newline="") as fh:
        wr = csv.writer(fh)
        wr.writerow(["run", "secret_type", "family", "n_samples", "detection_rate",
                     "ceiling", "ratio_uncapped", "retention_capped"])
        for run in run_keys:
            fam_c = _cells(rows, run, ["family", "secret_type"])
            for t in types:
                cn, ck = fam_c[(CONTROL_FAMILY, t)]
                ceil = ck / cn
                for f in families:
                    c = fam_c.get((f, t))
                    if not c:
                        continue
                    rate = c[1] / c[0]
                    ratio = rate / ceil if ceil > 0 else float("nan")
                    wr.writerow([run, t, f, c[0], f"{rate:.4f}", f"{ceil:.4f}",
                                 "" if ceil == 0 else f"{ratio:.4f}",
                                 "" if ceil == 0 else f"{min(ratio, 1.0):.4f}"])

    # ---- auditable ceilings with n ----
    with (outp / "ceilings.csv").open("w", newline="") as fh:
        wr = csv.writer(fh)
        wr.writerow(["run", "secret_type", "n_control", "k_detected", "ceiling",
                     "covered", "covered_at_min_ceiling"])
        for run in run_keys:
            fam_c = _cells(rows, run, ["family", "secret_type"])
            for t in types:
                n, k = fam_c[(CONTROL_FAMILY, t)]
                c = k / n
                wr.writerow([run, t, n, k, f"{c:.4f}", int(c > 0),
                             int(c > 0 and c >= min_ceiling)])

    # ---- raw rates by family (un-normalized) ----
    with (outp / "raw_rates.csv").open("w", newline="") as fh:
        wr = csv.writer(fh)
        wr.writerow(["family", "n_samples"] + run_keys)
        for f in families:
            fr = [r for r in rows if r["family"] == f]
            wr.writerow([f, len(fr)] + [f"{mean(r[k] for r in fr):.4f}" for k in run_keys])
        wr.writerow(["all_obfuscated", sum(fam_n[f] for f in obf)] +
                    [f"{mean(r[k] for r in rows if r['family'] != CONTROL_FAMILY):.4f}"
                     for k in run_keys])

    print(f"\nWrote retention_ci.csv, robustness_index_variants.csv, by_transformation.csv, "
          f"by_carrier.csv, by_type.csv, ceilings.csv, raw_rates.csv to {outp}/")


def main():
    ap = argparse.ArgumentParser(description="Ceiling-normalized robustness analysis")
    ap.add_argument("--matrix", required=True, help="path to detection_matrix.csv")
    ap.add_argument("--out", default="out/results",
                    help="output directory (default: out/results, so a run never "
                         "overwrites the committed results/)")
    ap.add_argument("--boot", type=int, default=2000,
                    help="bootstrap replicates for 95%% CIs (0 disables the extended analysis)")
    ap.add_argument("--seed", type=int, default=7, help="bootstrap RNG seed")
    ap.add_argument("--min-ceiling", type=float, default=0.0,
                    help="coverage threshold: exclude types whose plaintext ceiling is below this")
    args = ap.parse_args()
    rows, run_keys = load(args.matrix)
    result, families, types = analyze(rows, run_keys)
    report(result, run_keys, families, args.out)
    if args.boot > 0:
        extended_analysis(rows, run_keys, families, types, args.out,
                          boot=args.boot, seed=args.seed, min_ceiling=args.min_ceiling)


if __name__ == "__main__":
    main()
