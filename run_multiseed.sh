#!/usr/bin/env bash
# run_multiseed.sh -- regenerate the corpus under several seeds, scan each with
# all configurations inside the pinned container, then analyze natively.
#
# Usage:   ./run_multiseed.sh                # seeds 1337 2024 4242 7331 9001
#          SEEDS="1337 2024" ./run_multiseed.sh
#          SKIP_BUILD=1 ./run_multiseed.sh   # image already built
#
# Seed 1337 is the primary corpus (paper tables); the others quantify
# corpus-generation variance (reviewer request: multiple seeds, not one).
set -euo pipefail

SEEDS="${SEEDS:-1337 2024 4242 7331 9001}"
PER_COMBO="${PER_COMBO:-30}"
IMAGE="${IMAGE:-secretbench}"
OUT="${OUT:-out}"
BOOT="${BOOT:-2000}"

# Pinned scanner binaries are linux/amd64; on Apple Silicon emulate.
PLATFORM=""
if [[ "$(uname -m)" == "arm64" || "$(uname -m)" == "aarch64" ]]; then
  PLATFORM="--platform linux/amd64"
fi

if [[ -z "${SKIP_BUILD:-}" ]]; then
  echo "== building image ${IMAGE} ${PLATFORM}"
  docker build ${PLATFORM} -t "${IMAGE}" .
fi

mkdir -p "${OUT}"
for s in ${SEEDS}; do
  d="seed_${s}"
  if [[ -f "${OUT}/${d}/results/detection_matrix.csv" ]]; then
    echo "== ${d}: results exist, skipping scan"
  else
    echo "== ${d}: generate (per-combo ${PER_COMBO}) + scan"
    docker run --rm ${PLATFORM} -v "$PWD/${OUT}:/work/out" "${IMAGE}" bash -lc "
      python obfuscation_corpus_generator.py --outdir /work/out/${d}/corpus --per-combo ${PER_COMBO} --seed ${s} &&
      python harness.py --corpus /work/out/${d}/corpus --out /work/out/${d}/results"
  fi
  echo "== ${d}: analyze (bootstrap B=${BOOT})"
  python3 analyze.py --matrix "${OUT}/${d}/results/detection_matrix.csv" \
                     --out "${OUT}/${d}/results" --boot "${BOOT}"
done

echo "== aggregating across seeds"
python3 aggregate_seeds.py --seeds ${OUT}/seed_* --out "${OUT}/multiseed"
echo "done. Primary (seed 1337) results: ${OUT}/seed_1337/results ; cross-seed: ${OUT}/multiseed"
