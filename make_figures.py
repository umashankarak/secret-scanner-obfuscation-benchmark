#!/usr/bin/env python3
"""
make_figures.py
===============
Turns the benchmark outputs into publication-ready figures.

Reads (from a --results directory produced by harness.py + analyze.py):
    normalized_robustness.csv   run, family, raw, covered_only, retention
    coverage.json               run -> {covered, uncovered, ceilings{type:rate}}
    detection_matrix.csv        per-sample rows incl. transformation_id, depth

Writes to --out (default: <results>/figures), each as .pdf (vector, for LaTeX)
and .png (300 dpi preview):
    fig1_decode_retention   decode-off vs decode-on retention by family
    fig2_retention_heatmap  family x scanner retention heatmap
    fig3_coverage_matrix    scanner x secret-type detector coverage
    fig4_depth_ladder       detection vs Base64 encoding depth (single->triple)

Retention is CLAMPED to 1.0: "fraction surviving obfuscation" cannot exceed the
plaintext ceiling; values >1 are per-type sampling noise, not real signal.

Requires: matplotlib, numpy  (pip install matplotlib numpy)
Usage:
    python make_figures.py --results out/results30
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import LinearSegmentedColormap

# ---- publication styling ---------------------------------------------------
plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 10,
    "axes.titlesize": 11,
    "axes.labelsize": 10,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "figure.dpi": 120,
    "savefig.bbox": "tight",
})
# Okabe-Ito colourblind-safe palette
OI = {"blue": "#0072B2", "vermillion": "#D55E00", "green": "#009E73",
      "orange": "#E69F00", "sky": "#56B4E9", "purple": "#CC79A7",
      "yellow": "#F0E442", "grey": "#999999", "black": "#222222"}

FAMILY_ORDER = ["control", "contextual", "encoding", "multi_encoding",
                "indirection", "composition", "splitting", "char_format"]
FAMILY_LABEL = {f: f.replace("_", " ") for f in FAMILY_ORDER}


def clamp(x: float) -> float:
    return min(x, 1.0)


# ---------------------------------------------------------------------------
# loaders
# ---------------------------------------------------------------------------
def load_retention(results: Path):
    """-> {run: {family: retention_clamped}}"""
    data = defaultdict(dict)
    with (results / "normalized_robustness.csv").open() as fh:
        for row in csv.DictReader(fh):
            data[row["run"]][row["family"]] = clamp(float(row["retention"]))
    return data


def load_coverage(results: Path):
    return json.loads((results / "coverage.json").read_text())


def load_matrix(results: Path):
    with (results / "detection_matrix.csv").open() as fh:
        return list(csv.DictReader(fh))


def run_order(runs):
    """Stable, readable ordering of run keys."""
    pref = ["gitleaks/default", "gitleaks/decode", "betterleaks/default",
            "betterleaks/decode", "trufflehog/default"]
    return [r for r in pref if r in runs] + [r for r in runs if r not in pref]


def save(fig, out: Path, name: str):
    for ext in ("pdf", "png"):
        fig.savefig(out / f"{name}.{ext}", dpi=300)
    plt.close(fig)
    print(f"  wrote {name}.pdf / {name}.png")


# ---------------------------------------------------------------------------
# Figure 1: decode off vs on, retention by family (headline hardening result)
# ---------------------------------------------------------------------------
def fig_decode(retention, out: Path, scanner="gitleaks"):
    off_key, on_key = f"{scanner}/default", f"{scanner}/decode"
    if off_key not in retention or on_key not in retention:
        print(f"  [skip] fig1: {scanner} default/decode not both present")
        return
    fams = [f for f in FAMILY_ORDER if f != "control" and f in retention[off_key]]
    off = [100 * retention[off_key][f] for f in fams]
    on = [100 * retention[on_key][f] for f in fams]

    x = np.arange(len(fams))
    w = 0.38
    fig, ax = plt.subplots(figsize=(7.2, 3.6))
    ax.bar(x - w / 2, off, w, label="decode off (default)", color=OI["grey"])
    ax.bar(x + w / 2, on, w, label="decode on (--max-decode-depth)", color=OI["blue"])
    ax.set_xticks(x)
    ax.set_xticklabels([FAMILY_LABEL[f] for f in fams], rotation=30, ha="right")
    ax.set_ylabel("retention (% of plaintext-detectable\nsurviving obfuscation)")
    ax.set_ylim(0, 105)
    ax.set_title(f"Recursive decoding recovers Base64/Hex encodings ({scanner})")
    ax.legend(frameon=False, loc="upper right")
    ax.grid(axis="y", alpha=0.3)
    save(fig, out, "fig1_decode_retention")


# ---------------------------------------------------------------------------
# Figure 2: family x scanner retention heatmap
# ---------------------------------------------------------------------------
def fig_heatmap(retention, out: Path):
    runs = run_order(list(retention))
    fams = [f for f in FAMILY_ORDER if f in retention[runs[0]]]
    M = np.array([[100 * retention[r].get(f, 0.0) for r in runs] for f in fams])

    cmap = LinearSegmentedColormap.from_list("ret", ["#3b0f70", "#8c2981",
                                                     "#de4968", "#fca50a", "#fcffa4"])
    fig, ax = plt.subplots(figsize=(7.4, 4.2))
    im = ax.imshow(M, cmap=cmap, vmin=0, vmax=100, aspect="auto")
    ax.set_xticks(range(len(runs)))
    ax.set_xticklabels(runs, rotation=25, ha="right", fontsize=9)
    ax.set_yticks(range(len(fams)))
    ax.set_yticklabels([FAMILY_LABEL[f] for f in fams])
    for i in range(len(fams)):
        for j in range(len(runs)):
            v = M[i, j]
            ax.text(j, i, f"{v:.0f}", ha="center", va="center", fontsize=8,
                    color="white" if v < 55 else "black")
    cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    cbar.set_label("retention (%)")
    ax.set_title("Obfuscation robustness by family and scanner")
    save(fig, out, "fig2_retention_heatmap")


# ---------------------------------------------------------------------------
# Figure 3: detector coverage matrix (scanner x secret type)
# ---------------------------------------------------------------------------
def fig_coverage(coverage, out: Path):
    runs = run_order(list(coverage))
    types = sorted({t for r in runs for t in coverage[r]["ceilings"]})
    M = np.array([[coverage[r]["ceilings"].get(t, 0.0) for r in runs] for t in types])
    covered = (M > 0).astype(float)

    cmap = LinearSegmentedColormap.from_list("cov", ["#f0f0f0", OI["green"]])
    fig, ax = plt.subplots(figsize=(7.4, 4.6))
    ax.imshow(covered, cmap=cmap, vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(runs)))
    ax.set_xticklabels(runs, rotation=25, ha="right", fontsize=9)
    ax.set_yticks(range(len(types)))
    ax.set_yticklabels([t.replace("_", " ") for t in types])
    for i in range(len(types)):
        for j in range(len(runs)):
            mark = "\u2713" if covered[i, j] else "\u2717"
            ax.text(j, i, mark, ha="center", va="center",
                    color="white" if covered[i, j] else OI["vermillion"], fontsize=11)
    # coverage count above each column (clear of the rotated x labels)
    for j in range(len(runs)):
        n = int(covered[:, j].sum())
        ax.text(j, -0.72, f"{n}/{len(types)}", ha="center", va="bottom", fontsize=9,
                fontweight="bold", color=OI["black"], clip_on=False)
    ax.set_ylim(len(types) - 0.5, -0.9)
    ax.set_title("Detector coverage: which secret types each scanner\ndetects in plaintext (generic rule vs detector-specific)",
                 pad=14)
    save(fig, out, "fig3_coverage_matrix")


# ---------------------------------------------------------------------------
# Figure 4: detection vs Base64 encoding depth (single -> double -> triple)
# ---------------------------------------------------------------------------
def fig_depth(matrix, out: Path):
    # pure Base64 ladder: T1.1 (x1), T2.1 (x2), T2.2 (x3)
    ladder = {"T1.1": 1, "T2.1": 2, "T2.2": 3}
    runs = run_order([c for c in matrix[0] if "/" in c])
    # detection rate per (run, depth)
    agg = {r: {d: [0, 0] for d in (1, 2, 3)} for r in runs}
    for row in matrix:
        d = ladder.get(row["transformation_id"])
        if d is None:
            continue
        for r in runs:
            agg[r][d][1] += 1
            agg[r][d][0] += int(row[r])
    fig, ax = plt.subplots(figsize=(6.4, 3.8))
    styles = {"gitleaks/default": (OI["grey"], "o", "-"),
              "gitleaks/decode": (OI["blue"], "o", "-"),
              "betterleaks/decode": (OI["green"], "s", "--"),
              "trufflehog/default": (OI["vermillion"], "^", "-")}
    for r in runs:
        ys = [100 * agg[r][d][0] / agg[r][d][1] if agg[r][d][1] else 0 for d in (1, 2, 3)]
        color, marker, ls = styles.get(r, (OI["purple"], "d", ":"))
        ax.plot([1, 2, 3], ys, marker=marker, ls=ls, color=color, label=r, lw=2)
    ax.set_xticks([1, 2, 3])
    ax.set_xticklabels(["x1 (single)", "x2 (double)", "x3 (triple)"])
    ax.set_xlabel("Base64 encoding depth")
    ax.set_ylabel("detection rate (%)")
    ax.set_ylim(-3, 105)
    ax.set_title("Detection vs multi-encoding depth")
    ax.legend(frameon=False, fontsize=8)
    ax.grid(alpha=0.3)
    save(fig, out, "fig4_depth_ladder")


def main():
    ap = argparse.ArgumentParser(description="Publication figures for the secret-scanner benchmark")
    ap.add_argument("--results", required=True, help="dir with normalized_robustness.csv, coverage.json, detection_matrix.csv")
    ap.add_argument("--out", default=None, help="output dir (default: <results>/figures)")
    ap.add_argument("--scanner", default="gitleaks", help="scanner for the decode-comparison figure")
    args = ap.parse_args()

    results = Path(args.results)
    out = Path(args.out) if args.out else results / "figures"
    out.mkdir(parents=True, exist_ok=True)

    retention = load_retention(results)
    coverage = load_coverage(results)

    print(f"Generating figures -> {out}/")
    fig_decode(retention, out, scanner=args.scanner)
    fig_heatmap(retention, out)
    fig_coverage(coverage, out)
    if (results / "detection_matrix.csv").exists():
        fig_depth(load_matrix(results), out)
    else:
        print("  [skip] fig4: detection_matrix.csv not found")
    print("Done.")


if __name__ == "__main__":
    main()
