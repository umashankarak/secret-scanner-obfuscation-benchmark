# Hiding in Plain Sight: A Taxonomy and Benchmark for the Obfuscation Robustness of Secret Scanners

This repository contains the corpus generator, evaluation harness, analysis
scripts, and released artifacts for the paper *"Hiding in Plain Sight: A
Taxonomy and Benchmark for the Obfuscation Robustness of Secret Scanners."*

The benchmark measures how well secret scanners (Gitleaks, Betterleaks,
TruffleHog, and detect-secrets) detect credentials that have been deliberately **obfuscated** —
encoded, split, character-manipulated, and so on — while remaining recoverable
at run time. All secrets used are **synthetic and non-functional**; no real
credentials are collected, stored, or distributed.

> **Note on secret-scanning alerts.** The synthetic credentials in this
> repository are *format-valid* by design — that is the point of the benchmark —
> so automated scanners, including GitHub's own, flag them. Every value is
> randomly generated and authenticates against nothing. See `results/raw_reports/README.md`.

---

## Repository contents

| Path | Description |
|------|-------------|
| `obfuscation_corpus_generator.py` | Generates the synthetic, obfuscated corpus and a ground-truth manifest. |
| `harness.py` | Runs the scanners over the corpus, matches findings to the manifest, records rule attribution and wall-clock time, and computes detection metrics. |
| `analyze.py` | Computes ceiling-normalized robustness (retention), the robustness index and its variants, bootstrap confidence intervals, detector coverage, and the per-transformation / per-carrier / per-type breakdowns. |
| `make_figures.py` | Produces the paper's figures (PDF + PNG) from the analysis outputs. |
| `run_multiseed.sh` | Regenerates and scans the corpus under several seeds, then analyzes and aggregates. |
| `aggregate_seeds.py` | Mean / SD across seeds for retention, robustness-index variants, per-transformation results, and timing. |
| `Dockerfile` | Pins the four scanners at fixed versions and packages the tools + scripts. |
| `fixtures/` | Native-format scanner reports used by the harness `--selftest` mode. |
| `corpus/corpus.zip` | The exact 14,040-sample corpus and manifest used in the paper. |
| `results/` | The exact result files behind every table and figure in the paper. |
| `figures/` | The generated figures (PDF for print, PNG for preview). |

---

## Pinned tool versions

The results in the paper were produced with these exact versions:

| Scanner | Version |
|---------|---------|
| Gitleaks | 8.28.0 |
| Betterleaks | 1.1.1 |
| TruffleHog | 3.95.8 |
| detect-secrets | 1.5.0 |

Scanner behavior changes across releases, so these are pinned in the
`Dockerfile`. The versions actually used in a run are also recorded in
`results/tool_versions.json`.

The four scanners are evaluated under **six run configurations**: Gitleaks and
Betterleaks each with recursive decoding explicitly disabled
(`--max-decode-depth 0`) and enabled to depth 4, TruffleHog with verification
disabled, and detect-secrets with its default plugin set.

---

## Requirements

- **To reproduce the full pipeline (scanning):** Docker.
- **To reproduce only the analysis and figures:** Python 3.9+ with
  `matplotlib` and `numpy` (`pip install -r requirements.txt`). The generator,
  harness, and analysis scripts otherwise use only the Python standard library.

---

## Reproducing the results

All scripts write to `out/` by default, so nothing you run overwrites the
committed `results/` — compare your output against it.

### Option A — verify the numbers without running any scanner (fastest)

Every table and figure is derived from `results/detection_matrix.csv`, the
per-sample detection record. You can regenerate the full analysis and all
figures from it directly, with no Docker and no scanners:

```bash
pip install -r requirements.txt
python3 analyze.py --matrix results/detection_matrix.csv --out out/results_check
python3 make_figures.py --results out/results_check --matrix results/detection_matrix.csv
```

Compare `out/results_check/` and its figures against the committed `results/`
and `figures/` — the point estimates should match exactly. (Bootstrap interval
endpoints are reproducible for a given `--seed`, which defaults to 7.)

### Option B — reproduce end to end from scratch (with scanning)

This regenerates the corpus deterministically and re-runs all six scanner
configurations. It requires Docker.

```bash
# Build the image (pins Gitleaks 8.28.0, Betterleaks 1.1.1, TruffleHog 3.95.8, detect-secrets 1.5.0)
docker build -t secretbench .

# Generate the 14,040-sample corpus and scan it under all six configurations
docker run --rm -v "$PWD/out:/work/out" secretbench bash -lc '
  python obfuscation_corpus_generator.py --outdir /work/out/run30 --per-combo 30 --seed 1337 &&
  python harness.py --corpus /work/out/run30 --out /work/out/results30'

# Compute robustness metrics and figures (run natively on the host)
python3 analyze.py --matrix out/results30/detection_matrix.csv --out out/results30
python3 make_figures.py --results out/results30
```

(In Option B the matrix already sits in the same directory, so `--matrix` is not
needed; Figure 4 is drawn from it automatically.)

The fixed `--seed 1337` and `--per-combo 30` reproduce the identical corpus and
numbers reported in the paper. Compare `out/results30/` against the committed
`results/`.

**Apple Silicon / ARM hosts:** the pinned scanner binaries are `linux/amd64`, so
add `--platform linux/amd64` to both the `docker build` and `docker run`
commands. On native x86-64 hosts this flag is not needed.

### Option C — multiple seeds (corpus-generation variance)

A fixed seed establishes reproducibility but not stability across different
generated secret values. `run_multiseed.sh` repeats the entire benchmark —
generation, scanning under all six configurations, and analysis — on five
independently seeded corpora, then aggregates:

```bash
./run_multiseed.sh                       # seeds 1337 (primary) 2024 4242 7331 9001
SEEDS="1337 2024" ./run_multiseed.sh     # or a subset
SKIP_BUILD=1 ./run_multiseed.sh          # image already built
```

Per-seed results land in `out/seed_<n>/results/`; cross-seed mean and standard
deviation are written to `out/multiseed/` and are also committed under
`results/multiseed/`.

### Option D — run natively without Docker (optional)

Install the scanners on the host and run the harness directly:

```bash
brew install gitleaks
brew install betterleaks/betterleaks/betterleaks
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin v3.95.8
pip install detect-secrets==1.5.0

python3 obfuscation_corpus_generator.py --outdir out/run30 --per-combo 30 --seed 1337
python3 harness.py --corpus out/run30 --out out/results30
python3 analyze.py --matrix out/results30/detection_matrix.csv --out out/results30
python3 make_figures.py --results out/results30
```

Record the installed versions (the harness writes them to `tool_versions.json`);
they may differ from the pinned versions above.

---

## Pre-generated artifacts

For reviewers or readers who prefer not to run the pipeline:

- **`corpus/corpus.zip`** contains the exact corpus of 14,040 synthetic samples
  and the ground-truth `manifest.json`. Unzip to inspect individual samples
  (for example, to confirm that an "encoding" sample really is Base64-encoded,
  or that the secrets are synthetic).
- **`results/`** contains the exact output files behind the paper:
  - `detection_matrix.csv` — per-sample detection outcome for every run.
  - `summary_by_family.csv`, `summary.json`, `raw_rates.csv` — raw detection rates (Supplementary Table S1).
  - `normalized_robustness.csv` — ceiling-normalized retention (Table 6).
  - `retention_ci.csv` — retention with bootstrap 95% confidence intervals.
  - `robustness_index_variants.csv` — the index under four aggregations (Table 7).
  - `by_carrier.csv` — retention by carrier (Table 8).
  - `by_transformation.csv` — retention by individual transformation (Table 9).
  - `by_type.csv`, `ceilings.csv` — per-credential-type retention and auditable plaintext ceilings (Supplementary Table S2).
  - `detected_by_rule.csv` — which scanner rule or plugin produced each match.
  - `run_timing.json` — wall-clock scan time per configuration (Table 10).
  - `coverage.json` — detector coverage per scanner (Figure 5).
  - `multiseed/` — cross-seed mean and SD (Table 5).
  - `tool_versions.json` — the exact scanner versions used.
  - `raw_reports/` — unmodified native-format scanner output.

---

## Corpus structure

The generator produces a self-contained output directory:

```
run30/
├── manifest.json           # ground truth (NOT scanned)
└── corpus/                 # only this subtree is scanned
    ├── python/<type>/<transform>/sample_*.py
    ├── dotenv/<type>/<transform>/sample_*.env
    └── yaml/<type>/<transform>/sample_*.yaml
```

The manifest records, for each sample, its file, credential type, transformation
and family, encoding depth, carrier, plaintext value, and expected line(s). It
is written outside the scanned `corpus/` directory so it is never itself scanned.

---

## Ethics

All secrets in this repository are **synthetic**: randomly generated to be
format-valid (so scanner rules engage) but non-functional (they authenticate
against nothing). No real credentials were collected, stored, or released. The
individual obfuscation transformations studied are elementary and long known;
the contribution is their systematic organization and the empirical measurement
of scanner robustness, intended to help tool maintainers close detection gaps.

---

## License

Released under the MIT License. See `LICENSE`.

---

## Citation

If you use this benchmark, please cite the paper:

```bibtex
@article{kalaiah2026hiding,
  title   = {Hiding in Plain Sight: A Taxonomy and Benchmark for the
             Obfuscation Robustness of Secret Scanners},
  author  = {Kalaiah, Umashankara},
  journal = {IEEE Access},
  year    = {2026}
}
```
