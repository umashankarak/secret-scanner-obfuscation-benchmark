#!/usr/bin/env python3
"""
harness.py
==========
Runs secret scanners over the obfuscation-robustness corpus, normalizes each
tool's output into one canonical finding schema, matches findings against the
ground-truth manifest, and emits detection-rate / evasion tables.

Slice: Gitleaks, Betterleaks, TruffleHog  (3 binaries, 2 parsers -- Gitleaks
and Betterleaks share a JSON report format). Adding a scanner later = one more
adapter + one RunSpec.

Design notes baked in:
  * Two configs per Gitleaks-family tool: 'default' (decoding off) and 'decode'
    (--max-decode-depth N). The corpus encoding family (T1.1 Base64, T1.4 Hex,
    T1.5 URL) maps onto the decoders these tools support, so the decode-off vs
    decode-on gap is a headline result. Base32/Base85/Gzip are NOT supported
    decoders, so they should evade even with decoding on.
  * TruffleHog runs with verification OFF: fake secrets can't be verified and
    live API calls would be non-deterministic and abusive. We measure the
    detection stage only.
  * Scanners exit non-zero when they FIND secrets; that is success, not a crash.

The runner shells out to the real binaries (use the Docker image). Parsing,
matching and metrics are separated from the runner so they can be validated
offline with `--selftest` against fixture reports.

Usage:
    python harness.py --corpus corpus --out results
    python harness.py --corpus corpus --out results --tools gitleaks trufflehog
    python harness.py --selftest --corpus corpus --fixtures fixtures --out results
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Canonical finding + run specification
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    file: str                    # path as reported by the scanner
    line: Optional[int]          # 1-based line, or None
    rule_id: str                 # rule / detector name
    matched: str                 # captured secret text (may be redacted / empty)
    scanner: str
    config: str


@dataclass
class RunSpec:
    scanner: str                 # gitleaks | betterleaks | trufflehog
    config: str                  # default | decode
    binary: str                  # executable name
    extra: dict = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.scanner}/{self.config}"


DEFAULT_RUNS: List[RunSpec] = [
    RunSpec("gitleaks",    "default", "gitleaks",    {"decode_depth": 0}),
    RunSpec("gitleaks",    "decode",  "gitleaks",    {"decode_depth": 4}),
    RunSpec("betterleaks", "default", "betterleaks", {"decode_depth": 0}),
    RunSpec("betterleaks", "decode",  "betterleaks", {"decode_depth": 4}),
    RunSpec("trufflehog",  "default", "trufflehog",  {}),
]


# ---------------------------------------------------------------------------
# Parsers  (native tool output -> canonical Findings)
# ---------------------------------------------------------------------------
def parse_gitleaks_family(report_text: str, scanner: str, config: str) -> List[Finding]:
    """Gitleaks / Betterleaks JSON report: a JSON array of findings."""
    if not report_text.strip():
        return []
    data = json.loads(report_text)
    out: List[Finding] = []
    for d in data:
        out.append(Finding(
            file=d.get("File", ""),
            line=d.get("StartLine"),
            rule_id=d.get("RuleID", ""),
            matched=d.get("Secret") or d.get("Match") or "",
            scanner=scanner,
            config=config,
        ))
    return out


def parse_trufflehog(stdout_text: str, scanner: str, config: str) -> List[Finding]:
    """TruffleHog --json: newline-delimited JSON, one object per finding."""
    out: List[Finding] = []
    for raw in stdout_text.splitlines():
        raw = raw.strip()
        if not raw or not raw.startswith("{"):
            continue                     # skip stray log lines
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        fs = (obj.get("SourceMetadata", {}) or {}).get("Data", {}).get("Filesystem", {}) or {}
        out.append(Finding(
            file=fs.get("file", ""),
            line=fs.get("line"),
            rule_id=obj.get("DetectorName", ""),
            matched=obj.get("Raw") or obj.get("Redacted") or "",
            scanner=scanner,
            config=config,
        ))
    return out


# ---------------------------------------------------------------------------
# Runners  (shell out to the real binaries)
# ---------------------------------------------------------------------------
def _tool_version(binary: str) -> str:
    for args in ([binary, "version"], [binary, "--version"]):
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=30)
            v = (r.stdout or r.stderr).strip().splitlines()
            if v:
                return v[0]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return "unknown"


def run_gitleaks_family(spec: RunSpec, corpus: Path, workdir: Path) -> List[Finding]:
    report = workdir / f"{spec.scanner}_{spec.config}.json"
    cmd = [
        spec.binary, "dir", str(corpus),
        "--report-format", "json",
        "--report-path", str(report),
        "--no-banner",
        "--exit-code", "0",            # do not fail the process when leaks are found
        "--max-decode-depth", str(spec.extra.get("decode_depth", 0)),
    ]
    subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    text = report.read_text(encoding="utf-8") if report.exists() else ""
    return parse_gitleaks_family(text, spec.scanner, spec.config)


def run_trufflehog(spec: RunSpec, corpus: Path, workdir: Path) -> List[Finding]:
    cmd = [
        spec.binary, "filesystem", str(corpus),
        "--json",
        "--no-verification",           # fake secrets: never make live API calls
        "--concurrency", "4",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    (workdir / "trufflehog_default.ndjson").write_text(r.stdout, encoding="utf-8")
    return parse_trufflehog(r.stdout, spec.scanner, spec.config)


def run_spec(spec: RunSpec, corpus: Path, workdir: Path) -> List[Finding]:
    if spec.scanner in ("gitleaks", "betterleaks"):
        return run_gitleaks_family(spec, corpus, workdir)
    if spec.scanner == "trufflehog":
        return run_trufflehog(spec, corpus, workdir)
    raise ValueError(f"unknown scanner: {spec.scanner}")


# ---------------------------------------------------------------------------
# Matcher  (findings x manifest entry -> detected?)
# ---------------------------------------------------------------------------
def _rel(path: str, root_prefix: str) -> str:
    """Relative path of a scanner finding via pure string ops (no filesystem
    calls). Handles reports produced in a different environment (e.g. written
    inside a container as /work/.../corpus/... but matched on the host) by
    normalizing on the '/corpus/' marker, so matching stays fast either way."""
    p = path.replace("\\", "/")
    if p.startswith(root_prefix):
        return p[len(root_prefix):]
    i = p.rfind("/corpus/")
    if i != -1:
        return p[i + len("/corpus/"):]
    return p.lstrip("./")


def index_findings(findings: List[Finding], root: Path) -> Dict[str, List[Finding]]:
    """Group findings by file path relative to the scan dir, so each manifest
    entry only compares against findings in its own file. Turns an
    O(entries x findings) scan (with a filesystem call per finding) into an
    O(entries) dict lookup -- the difference between hours and seconds."""
    root_prefix = str(root.resolve()).replace("\\", "/").rstrip("/") + "/"
    by_file: Dict[str, List[Finding]] = {}
    for f in findings:
        by_file.setdefault(_rel(f.file, root_prefix), []).append(f)
    return by_file


def _entry_targets(entry: dict):
    comps = entry.get("components")
    if comps:
        targets = [(c.get("line"), c["value"]) for c in comps]
    else:
        targets = [(entry["expected_line"], entry["secret_value"])]
    want_lines = {ln for ln, _ in targets if ln is not None}
    want_values = [v for _, v in targets]
    return want_lines, want_values


def is_detected(entry: dict, by_file: Dict[str, List[Finding]]) -> bool:
    """
    A sample is 'detected' if some finding IN ITS FILE lands on an expected line
    or its captured text matches a planted secret value. Composite secrets
    (aws_keypair) count as detected if the scanner flags ANY component.
    `by_file` is the per-run index from index_findings().
    """
    want_file = entry["file"].replace("\\", "/")
    want_lines, want_values = _entry_targets(entry)

    candidates = by_file.get(want_file)
    if candidates is None:               # rare: fall back to suffix match
        candidates = [f for rel, fs in by_file.items()
                      if rel.endswith(want_file) or want_file.endswith(rel)
                      for f in fs]
    for f in candidates:
        if f.line is not None and f.line in want_lines:
            return True
        if f.matched:
            for v in want_values:
                if v in f.matched or (len(f.matched) >= 6 and f.matched in v):
                    return True
    return False


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def build_results(manifest: List[dict], per_run_findings: Dict[str, List[Finding]],
                  root: Path) -> List[dict]:
    """One row per sample with a detected flag per run key."""
    indexed = {key: index_findings(fs, root) for key, fs in per_run_findings.items()}
    rows = []
    for entry in manifest:
        row = {
            "id": entry["id"],
            "secret_type": entry["secret_type"],
            "transformation_id": entry["transformation_id"],
            "family": entry["family"],
            "depth": entry["depth"],
            "carrier": entry["carrier"],
        }
        for key, by_file in indexed.items():
            row[key] = int(is_detected(entry, by_file))
        rows.append(row)
    return rows


def rate(rows: List[dict], key: str, predicate=lambda r: True) -> float:
    sel = [r for r in rows if predicate(r)]
    return (sum(r[key] for r in sel) / len(sel)) if sel else 0.0


def summarize(rows: List[dict], run_keys: List[str]) -> dict:
    families = sorted({r["family"] for r in rows})
    depths = sorted({r["depth"] for r in rows})
    summary = {"overall": {}, "by_family": {}, "by_depth": {}, "robustness_index": {}}
    for k in run_keys:
        summary["overall"][k] = rate(rows, k)
        summary["by_family"][k] = {
            fam: rate(rows, k, lambda r, f=fam: r["family"] == f) for fam in families
        }
        summary["by_depth"][k] = {
            d: rate(rows, k, lambda r, dd=d: r["depth"] == dd) for d in depths
        }
        # Robustness index: mean detection across non-control families (equal weight)
        obf = [f for f in families if f != "control"]
        vals = [summary["by_family"][k][f] for f in obf]
        summary["robustness_index"][k] = sum(vals) / len(vals) if vals else 0.0
    return summary


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def _pct(x: float) -> str:
    return f"{100 * x:5.1f}%"


def write_and_print(rows: List[dict], summary: dict, run_keys: List[str], out: Path):
    out.mkdir(parents=True, exist_ok=True)

    # per-sample detection matrix
    with (out / "detection_matrix.csv").open("w", newline="") as fh:
        cols = ["id", "secret_type", "transformation_id", "family", "depth", "carrier"] + run_keys
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    # by-family table
    families = sorted({r["family"] for r in rows})
    with (out / "summary_by_family.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["family"] + run_keys)
        for fam in families:
            w.writerow([fam] + [f"{summary['by_family'][k][fam]:.4f}" for k in run_keys])

    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    # console report
    width = max(len(k) for k in run_keys)
    print("\n=== Detection rate by transformation family ===")
    print("family".ljust(16) + "".join(k.rjust(width + 2) for k in run_keys))
    for fam in families:
        print(fam.ljust(16) + "".join(_pct(summary["by_family"][k][fam]).rjust(width + 2)
                                       for k in run_keys))
    print("\n=== Overall & robustness index ===")
    print("overall".ljust(16) + "".join(_pct(summary["overall"][k]).rjust(width + 2)
                                         for k in run_keys))
    print("robustness_idx".ljust(16) + "".join(_pct(summary["robustness_index"][k]).rjust(width + 2)
                                                for k in run_keys))
    print(f"\nWrote detection_matrix.csv, summary_by_family.csv, summary.json to {out}/")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def load_manifest(corpus: Path) -> List[dict]:
    return json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))


def scan_dir_for(root: Path) -> Path:
    """Samples live under <root>/corpus (v2 layout); older corpora scanned <root>
    directly. Return whichever exists, so the ground-truth manifest.json -- which
    sits at <root>/manifest.json, OUTSIDE the sample tree -- is never scanned."""
    sub = root / "corpus"
    return sub if sub.is_dir() else root


def load_reports_from_dir(workdir: Path, runs: List[RunSpec]) -> Dict[str, List[Finding]]:
    """Reuse scanner reports already written to <workdir> instead of re-scanning.
    Lets you re-do matching/metrics in seconds after a completed (slow) scan."""
    per_run: Dict[str, List[Finding]] = {}
    for spec in runs:
        if spec.scanner == "trufflehog":
            fp = workdir / "trufflehog_default.ndjson"
            parser = parse_trufflehog
        else:
            fp = workdir / f"{spec.scanner}_{spec.config}.json"
            parser = parse_gitleaks_family
        if fp.exists():
            per_run[spec.key] = parser(fp.read_text(encoding="utf-8"),
                                       spec.scanner, spec.config)
            print(f"[loaded] {spec.key}: {len(per_run[spec.key])} findings from {fp.name}")
        else:
            print(f"[skip]   {spec.key}: no report at {fp}")
    return per_run


def live_run(corpus: Path, out: Path, tools: List[str], from_reports: bool = False):
    runs = [r for r in DEFAULT_RUNS if r.scanner in tools]
    if not runs:
        sys.exit(f"no runs selected for tools={tools}")
    workdir = out / "raw_reports"
    workdir.mkdir(parents=True, exist_ok=True)
    manifest = load_manifest(corpus)
    scan_dir = scan_dir_for(corpus)

    if from_reports:
        print(f"[from-reports] reusing reports in {workdir} (no scanning)")
        per_run = load_reports_from_dir(workdir, runs)
    else:
        print(f"[scan target] {scan_dir}   (manifest read from {corpus / 'manifest.json'})")
        per_run = {}
        versions: Dict[str, str] = {}
        for spec in runs:
            print(f"[run] {spec.key}  ({spec.binary})")
            versions[spec.binary] = _tool_version(spec.binary)
            per_run[spec.key] = run_spec(spec, scan_dir, workdir)
            print(f"      {len(per_run[spec.key])} findings")
        (out / "tool_versions.json").write_text(json.dumps(versions, indent=2), encoding="utf-8")

    run_keys = [r.key for r in runs if r.key in per_run]
    print("[match] indexing findings and matching against manifest ...")
    rows = build_results(manifest, per_run, scan_dir)
    summary = summarize(rows, run_keys)
    write_and_print(rows, summary, run_keys, out)


def selftest(corpus: Path, fixtures: Path, out: Path):
    """
    Validate parse -> match -> metrics WITHOUT the binaries, using fixture
    reports written in each tool's exact native schema. This checks the
    pipeline logic; real detection numbers require live_run in the container.
    """
    manifest = load_manifest(corpus)
    scan_dir = scan_dir_for(corpus)
    per_run: Dict[str, List[Finding]] = {}

    gl = (fixtures / "gitleaks_default.json")
    if gl.exists():
        per_run["gitleaks/default"] = parse_gitleaks_family(
            gl.read_text(), "gitleaks", "default")
    th = (fixtures / "trufflehog_default.ndjson")
    if th.exists():
        per_run["trufflehog/default"] = parse_trufflehog(
            th.read_text(), "trufflehog", "default")

    run_keys = list(per_run.keys())
    rows = build_results(manifest, per_run, scan_dir)
    summary = summarize(rows, run_keys)

    print("SELFTEST: parsed fixtures ->",
          {k: len(v) for k, v in per_run.items()})
    write_and_print(rows, summary, run_keys, out)
    # spot-check: report which sampled ids the fixtures marked detected
    hits = {k: [r["id"] for r in rows if r[k]] for k in run_keys}
    print("\nSELFTEST detected ids:", json.dumps(hits, indent=2))


def main():
    ap = argparse.ArgumentParser(description="Secret-scanner obfuscation-robustness harness")
    ap.add_argument("--corpus", required=True,
                    help="generator output root (contains manifest.json and corpus/)")
    ap.add_argument("--out", default="results")
    ap.add_argument("--tools", nargs="+", default=["gitleaks", "betterleaks", "trufflehog"],
                    choices=["gitleaks", "betterleaks", "trufflehog"])
    ap.add_argument("--selftest", action="store_true",
                    help="validate parser/matcher/metrics on fixture reports (no binaries)")
    ap.add_argument("--fixtures", default="fixtures")
    ap.add_argument("--from-reports", action="store_true",
                    help="reuse scanner reports already in <out>/raw_reports/ and just "
                         "re-run matching/metrics (skips scanning)")
    args = ap.parse_args()

    corpus, out = Path(args.corpus), Path(args.out)
    if args.selftest:
        selftest(corpus, Path(args.fixtures), out)
    else:
        live_run(corpus, out, args.tools, from_reports=args.from_reports)


if __name__ == "__main__":
    main()
