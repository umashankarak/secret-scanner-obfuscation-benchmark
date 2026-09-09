# Secret-scanner obfuscation-robustness benchmark
# ------------------------------------------------
# Pins the four scanners + the harness/generator so the
# study is reproducible. Rebuild = same tool versions = same numbers.
#
# Build:
#   docker build -t secretbench .
#
# Run (generate corpus + scan + metrics), mounting a host dir for results:
#   docker run --rm -v "$PWD/out:/work/out" secretbench bash -lc '
#     python obfuscation_corpus_generator.py --outdir /work/out/corpus --per-combo 30 --seed 1337 &&
#     python harness.py --corpus /work/out/corpus --out /work/out/results'
#
# NOTE ON PINS: version numbers below are set at authoring time. TruffleHog
# releases frequently -- confirm the current tag on the releases page and set
# --build-arg TRUFFLEHOG_VERSION=... so your paper cites the exact version.

FROM python:3.12-slim

ARG GITLEAKS_VERSION=8.28.0
ARG BETTERLEAKS_VERSION=1.1.1
ARG TRUFFLEHOG_VERSION=3.95.8          # <-- verify against current release, then pin
ARG DETECT_SECRETS_VERSION=1.5.0

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates git tar \
    && rm -rf /var/lib/apt/lists/*

# --- Gitleaks (regex + Shannon entropy) ---
RUN curl -sSL -o /tmp/gl.tar.gz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    && tar -xzf /tmp/gl.tar.gz -C /usr/local/bin gitleaks \
    && rm /tmp/gl.tar.gz \
    && gitleaks version

# --- Betterleaks (regex + BPE token-efficiency; drop-in Gitleaks successor) ---
RUN curl -sSL -o /tmp/bl.tar.gz \
      "https://github.com/betterleaks/betterleaks/releases/download/v${BETTERLEAKS_VERSION}/betterleaks_${BETTERLEAKS_VERSION}_linux_x64.tar.gz" \
    && tar -xzf /tmp/bl.tar.gz -C /usr/local/bin betterleaks \
    && rm /tmp/bl.tar.gz \
    && betterleaks version

# --- TruffleHog (detector-based + optional live verification) ---
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
      | sh -s -- -b /usr/local/bin "v${TRUFFLEHOG_VERSION}" \
    && trufflehog --version

# --- detect-secrets (Yelp; plugin-based: provider regexes + keyword + entropy) ---
# Revision: third independent detection lineage, not derived from Gitleaks or TruffleHog.
RUN pip install --no-cache-dir "detect-secrets==${DETECT_SECRETS_VERSION}" \
    && detect-secrets --version

WORKDIR /work
COPY obfuscation_corpus_generator.py harness.py ./

# Record the pinned versions inside the image for provenance
RUN { echo "gitleaks=$(gitleaks version 2>&1 | head -1)"; \
      echo "betterleaks=$(betterleaks version 2>&1 | head -1)"; \
      echo "trufflehog=$(trufflehog --version 2>&1 | head -1)"; \
      echo "detect-secrets=$(detect-secrets --version 2>&1 | head -1)"; } > /work/TOOL_VERSIONS.txt

CMD ["bash"]
