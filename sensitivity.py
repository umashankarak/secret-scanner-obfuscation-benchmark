#!/usr/bin/env python3
"""
sensitivity.py -- rule-level sensitivity analyses for the obfuscation benchmark
===============================================================================

Every analysis here is recomputed from files the harness already writes. No
scanner is re-run.

Inputs
  detection_matrix.csv     per-sample detection flag per run
  sample_rule_matrix.csv   per-sample (rule_id, match_type) per run

Analyses
  1. Type-consistent matching   A detection counts only when the rule that fired
     is designed to find the credential type that was planted (or is a generic
     high-entropy/keyword rule). Excludes wrong-type credits such as TruffleHog's
     Wit.ai detector firing on an AWS key.
  2. Identifier-independent     A detection counts only when the rule does not
     require a secret-looking identifier nearby. Isolates value-based detection
     from detection driven by the benchmark's own variable names.
  3. detect-secrets without its keyword plugin (a special case of 2).
  4. Contextual merge           T6.1 and T6.4 emit identical files; the family is
     recomputed as a single condition.
  5. Clopper-Pearson bounds     Exact one-sided bounds for cells at 0% or 100%,
     where a bootstrap interval has zero width.
  6. Match-type counts          How many detections rest on line position, on an
     exact value match, or on both.

Usage
  python3 sensitivity.py --matrix results/detection_matrix.csv \
                         --rules  results/sample_rule_matrix.csv \
                         --out    out/sensitivity
"""
from __future__ import annotations

import argparse
import csv
import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set

META = ["id", "secret_type", "transformation_id", "family", "depth", "carrier"]
CONTROL = "control"

# Credential types each provider-specific rule is designed to find. None = the
# rule is generic (entropy or keyword based) and applies to any planted type.
AWS_TYPES = {"aws_access_key_id", "aws_secret_access_key", "aws_keypair"}
RULE_TYPES: Dict[str, Set[str] | None] = {
    # Gitleaks / Betterleaks
    "aws-access-token": AWS_TYPES,
    "github-pat": {"github_pat"},
    "gcp-api-key": {"google_api_key"},
    "jwt": {"jwt"},
    "jwt-base64": {"jwt"},
    "slack-bot-token": {"slack_bot_token"},
    "stripe-access-token": {"stripe_secret_key"},
    "generic-api-key": None,
    # TruffleHog
    "AWS": AWS_TYPES,
    "Github": {"github_pat"},
    "Slack": {"slack_bot_token"},
    "Stripe": {"stripe_secret_key"},
    "GoogleGeminiAPIKey": {"google_api_key"},
    "JWT": {"jwt"},
    "Wit": set(),            # Wit.ai tokens are not planted: never type-consistent
    # detect-secrets
    "AWS Access Key": AWS_TYPES,
    "GitHub Token": {"github_pat"},
    "JSON Web Token": {"jwt"},
    "Stripe Access Key": {"stripe_secret_key"},
    "Slack Token": {"slack_bot_token"},
    "Base64 High Entropy String": None,
    "Hex High Entropy String": None,
    "Secret Keyword": None,
}

# Rules that fire only when a secret-looking identifier sits nearby.
KEYWORD_GATED = {"generic-api-key", "Secret Keyword"}

DUPLICATE_CONTEXTUAL = "T6.4"   # identical to T6.1; dropped when merging


def load(matrix: str, rules: str):
    rows: List[dict] = []
    with open(matrix, newline="") as fh:
        r = csv.DictReader(fh)
        runs = [c for c in r.fieldnames if c not in META]
        for d in r:
            for k in runs:
                d[k] = int(d[k])
            rows.append(d)
    per_sample: Dict[tuple, List[tuple]] = defaultdict(list)
    unknown: Set[str] = set()
    with open(rules, newline="") as fh:
        for d in csv.DictReader(fh):
            per_sample[(d["id"], d["run"])].append((d["rule_id"], d["match_type"]))
            if d["rule_id"] not in RULE_TYPES:
                unknown.add(d["rule_id"])
    return rows, runs, per_sample, unknown


def keep(rule: str, stype: str, mode: str) -> bool:
    """Does this rule survive the given filter for a sample of type `stype`?"""
    if mode == "all":
        return True
    if mode == "type_consistent":
        t = RULE_TYPES.get(rule, None)       # unknown rules treated as generic
        return True if t is None else stype in t
    if mode == "identifier_independent":
        return rule not in KEYWORD_GATED
    raise ValueError(mode)


def detections(rows, runs, per_sample, mode: str, merge_contextual: bool):
    """-> det[(run, family, secret_type)] = [n, k]  and the per-type control ceiling."""
    det = defaultdict(lambda: [0, 0])
    for r in rows:
        if merge_contextual and r["transformation_id"] == DUPLICATE_CONTEXTUAL:
            continue
        for run in runs:
            hit = False
            if r[run]:
                hit = any(keep(rule, r["secret_type"], mode)
                          for rule, _how in per_sample.get((r["id"], run), []))
            c = det[(run, r["family"], r["secret_type"])]
            c[0] += 1
            c[1] += int(hit)
    return det


def retention(det, runs, families, types):
    """Ceiling-normalized retention, recomputing ceilings under the same filter."""
    out = {}
    for run in runs:
        ceil = {}
        for t in types:
            n, k = det.get((run, CONTROL, t), [0, 0])
            ceil[t] = (k / n) if n else 0.0
        covered = [t for t in types if ceil[t] > 0]
        fam = {}
        for f in families:
            vals = []
            for t in covered:
                n, k = det.get((run, f, t), [0, 0])
                if n:
                    vals.append(min((k / n) / ceil[t], 1.0))
            fam[f] = sum(vals) / len(vals) if vals else 0.0
        out[run] = {"family": fam, "covered": covered, "ceilings": ceil}
    return out


def indices(fam: Dict[str, float], fam_n: Dict[str, int]):
    obf = [f for f in fam if f != CONTROL]
    nc = [f for f in obf if f != "contextual"]
    def unw(fs): return sum(fam[f] for f in fs) / len(fs) if fs else 0.0
    def wt(fs):
        tot = sum(fam_n.get(f, 0) for f in fs)
        return sum(fam[f] * fam_n.get(f, 0) for f in fs) / tot if tot else 0.0
    return {"unweighted": unw(obf), "unweighted_excl_contextual": unw(nc),
            "sample_weighted": wt(obf), "sample_weighted_excl_contextual": wt(nc)}


def clopper_pearson_degenerate(k: int, n: int, conf: float = 0.95):
    """Exact one-sided bound for the cells a bootstrap cannot bound: k=0 or k=n."""
    a = (1 - conf) / 2
    if n == 0:
        return (0.0, 1.0)
    if k == 0:
        return (0.0, 1 - a ** (1 / n))
    if k == n:
        return (a ** (1 / n), 1.0)
    return (None, None)


def main():
    ap = argparse.ArgumentParser(description="Rule-level sensitivity analyses")
    ap.add_argument("--matrix", required=True)
    ap.add_argument("--rules", required=True)
    ap.add_argument("--out", default="out/sensitivity")
    a = ap.parse_args()

    outp = Path(a.out); outp.mkdir(parents=True, exist_ok=True)
    rows, runs, per_sample, unknown = load(a.matrix, a.rules)
    if unknown:
        print(f"[warn] rules not in RULE_TYPES (treated as generic): {sorted(unknown)}")

    families = sorted({r["family"] for r in rows})
    types = sorted({r["secret_type"] for r in rows})

    scenarios = [
        ("published",              "all",                     False),
        ("type_consistent",        "type_consistent",         False),
        ("identifier_independent", "identifier_independent",  False),
        ("contextual_merged",      "all",                     True),
        ("type_consistent+merged", "type_consistent",         True),
    ]

    fam_rows, idx_rows = [], []
    for name, mode, merge in scenarios:
        det = detections(rows, runs, per_sample, mode, merge)
        fam_n = defaultdict(int)
        for (run, f, t), (n, _k) in det.items():
            if run == runs[0]:
                fam_n[f] += n
        res = retention(det, runs, families, types)
        for run in runs:
            for f in families:
                fam_rows.append([name, run, f, fam_n[f], f"{res[run]['family'][f]:.4f}"])
            iv = indices(res[run]["family"], fam_n)
            for k, v in iv.items():
                idx_rows.append([name, run, k, f"{v:.4f}"])
            idx_rows.append([name, run, "coverage",
                             f"{len(res[run]['covered'])}/{len(types)}"])

    with (outp / "retention_scenarios.csv").open("w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["scenario", "run", "family", "n_samples", "retention"])
        w.writerows(fam_rows)
    with (outp / "index_scenarios.csv").open("w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["scenario", "run", "variant", "value"])
        w.writerows(idx_rows)

    # ---- match-type counts (Reviewer 2, new concern 3) ----
    mt = defaultdict(lambda: defaultdict(int))
    for (sid, run), lst in per_sample.items():
        hows = {how for _r, how in lst}
        bucket = ("value_or_both" if ("value" in hows or "both" in hows) else "line_only")
        mt[run][bucket] += 1
        for _r, how in lst:
            mt[run]["rule_" + how] += 1
    with (outp / "match_type_counts.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["run", "samples_line_only", "samples_value_or_both",
                    "rulehits_line", "rulehits_value", "rulehits_both"])
        for run in runs:
            d = mt[run]
            w.writerow([run, d["line_only"], d["value_or_both"],
                        d["rule_line"], d["rule_value"], d["rule_both"]])

    # ---- exact bounds for degenerate cells ----
    det = detections(rows, runs, per_sample, "all", False)
    with (outp / "exact_bounds.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["run", "family", "n", "k", "rate", "cp95_lo", "cp95_hi", "note"])
        for run in runs:
            for f in families:
                n = sum(det[(run, f, t)][0] for t in types)
                k = sum(det[(run, f, t)][1] for t in types)
                lo, hi = clopper_pearson_degenerate(k, n)
                if lo is None:
                    continue
                w.writerow([run, f, n, k, f"{k/n:.4f}", f"{lo:.5f}", f"{hi:.5f}",
                            "zero detections" if k == 0 else "all detected"])

    # ---- console summary ----
    idx = defaultdict(dict)
    for name, run, var, val in idx_rows:
        idx[(run, var)][name] = val
    print("\n=== Robustness index under each scenario ===")
    names = [s[0] for s in scenarios]
    print(f"{'run':24}{'variant':34}" + "".join(f"{n[:20]:>22}" for n in names))
    for run in runs:
        for var in ["unweighted", "unweighted_excl_contextual", "coverage"]:
            cells = []
            for n in names:
                v = idx[(run, var)].get(n, "-")
                cells.append(f"{(100*float(v)):.1f}".rjust(22) if var != "coverage" else v.rjust(22))
            print(f"{run:24}{var:34}" + "".join(cells))
    print(f"\nWrote retention_scenarios.csv, index_scenarios.csv, match_type_counts.csv, "
          f"exact_bounds.csv to {outp}/")


if __name__ == "__main__":
    main()
