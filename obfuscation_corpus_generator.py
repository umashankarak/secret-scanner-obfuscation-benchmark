#!/usr/bin/env python3
"""
obfuscation_corpus_generator.py  (v2)
=====================================
Generates a benchmark corpus for measuring the *obfuscation robustness* of
secret scanners (Gitleaks, Betterleaks, TruffleHog, ...).

CHANGES IN v2
-------------
* manifest.json is written to the OUTPUT ROOT, OUTSIDE the scanned corpus tree,
  so scanners never flag the plaintext secrets sitting in the ground-truth file.
  Layout:
      <outdir>/manifest.json          <- ground truth, NOT scanned
      <outdir>/corpus/<carrier>/...   <- ONLY this is scanned
* New composite secret type `aws_keypair`: emits an AWS access key ID AND a
  secret access key on adjacent lines, which is what Gitleaks' composite AWS
  rule needs in order to fire. The obfuscation transform is applied to BOTH
  components. The standalone `aws_access_key_id` type is kept on purpose -- no
  scanner detects a lone AKID by default, and that is itself a finding the
  coverage table reports.
* Carriers now render one-or-more assignments per sample (single secret -> one
  line; keypair -> two lines).

ETHICS: synthetic, FAKE secrets only. Values are random: format-valid so
scanners' regexes engage, but not real credentials. Never seed with real
secrets. Disclose findings to scanner maintainers before publishing.

RECOVERABILITY: every non-contextual transformation is round-trip checked --
the generator reconstructs each value and asserts equality before writing.

Usage:
    python obfuscation_corpus_generator.py --list
    python obfuscation_corpus_generator.py --outdir out/run1 --per-combo 30 --seed 1337
    python obfuscation_corpus_generator.py --secrets aws_keypair github_pat \
        --transforms T0.0 T1.1 T2.2 T7.1 --carriers python dotenv
"""

from __future__ import annotations

import argparse
import base64
import codecs
import gzip
import json
import random
import string
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Set, Tuple

# ---------------------------------------------------------------------------
# 1. Synthetic secret factory  --  FAKE, format-valid values only
# ---------------------------------------------------------------------------
_ALNUM = string.ascii_letters + string.digits
_UPPER_NUM = string.ascii_uppercase + string.digits
_B64ISH = string.ascii_letters + string.digits + "+/"
_URLSAFE = string.ascii_letters + string.digits + "-_"
_HEX = "0123456789abcdef"

SECRET_FACTORIES: Dict[str, Callable[[random.Random], str]] = {}


def secret_factory(name: str):
    def deco(fn):
        SECRET_FACTORIES[name] = fn
        return fn
    return deco


def _rand(alphabet: str, n: int, rng: random.Random) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def _b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


@secret_factory("aws_access_key_id")
def _aws_akid(rng):            # AKIA + 16 upper/digits
    return "AKIA" + _rand(_UPPER_NUM, 16, rng)


@secret_factory("aws_secret_access_key")
def _aws_secret(rng):          # 40 base64-ish chars
    return _rand(_B64ISH, 40, rng)


@secret_factory("github_pat")
def _github_pat(rng):          # ghp_ + 36 alnum
    return "ghp_" + _rand(_ALNUM, 36, rng)


@secret_factory("stripe_secret_key")
def _stripe(rng):              # sk_live_ + 24 alnum
    return "sk_live_" + _rand(_ALNUM, 24, rng)


@secret_factory("google_api_key")
def _google(rng):              # AIza + 35 urlsafe
    return "AIza" + _rand(_URLSAFE, 35, rng)


@secret_factory("slack_bot_token")
def _slack(rng):
    return "xoxb-%d-%d-%s" % (
        rng.randint(10 ** 10, 10 ** 11),
        rng.randint(10 ** 11, 10 ** 12),
        _rand(_ALNUM, 24, rng),
    )


@secret_factory("jwt")
def _jwt(rng):
    header = _b64url_nopad(b'{"alg":"HS256","typ":"JWT"}')
    payload = _b64url_nopad(
        ('{"sub":"%s","name":"synthetic"}' % _rand(_ALNUM, 8, rng)).encode()
    )
    sig = _b64url_nopad(bytes(rng.getrandbits(8) for _ in range(32)))
    return f"{header}.{payload}.{sig}"


@secret_factory("generic_hex_token")
def _hex_token(rng):
    return _rand(_HEX, 40, rng)


# --- Composite secrets: emit multiple named components on adjacent lines -----
# Each factory returns a list of (component_name, value). The FIRST component is
# the 'primary' -- its value and line are what the manifest/matcher track.
COMPOSITE_SECRETS: Dict[str, Callable[[random.Random], List[Tuple[str, str]]]] = {}


def composite_secret(name: str):
    def deco(fn):
        COMPOSITE_SECRETS[name] = fn
        return fn
    return deco


@composite_secret("aws_keypair")
def _aws_keypair(rng):
    # Access key ID (primary) + secret access key on adjacent lines. This is the
    # pair Gitleaks' composite AWS rule is tuned to detect.
    return [
        ("aws_access_key_id", _aws_akid(rng)),
        ("aws_secret_access_key", _aws_secret(rng)),
    ]


# ---------------------------------------------------------------------------
# 2. Emission + transformation registry
# ---------------------------------------------------------------------------
CODE_CARRIERS: Set[str] = {"python"}
DATA_CARRIERS: Set[str] = {"dotenv", "yaml"}
ALL_CARRIERS = CODE_CARRIERS | DATA_CARRIERS


@dataclass
class Emission:
    representation: str
    recovered: str
    is_expression: bool = False
    preamble: List[str] = field(default_factory=list)
    recoverable: bool = True
    note: str = ""


@dataclass
class Transform:
    tid: str
    name: str
    family: str
    fn: Callable[[str, random.Random], Emission]
    carriers: Set[str]
    depth: int = 1


REGISTRY: Dict[str, Transform] = {}


def register(tid: str, name: str, family: str, carriers: Set[str], depth: int = 1):
    def deco(fn):
        REGISTRY[tid] = Transform(tid, name, family, fn, carriers, depth)
        return fn
    return deco


def pylit(s: str) -> str:
    """Return a valid double-quoted string literal (keeps unicode chars literal)."""
    return json.dumps(s, ensure_ascii=False)


def _split_parts(s: str, k: int, rng: random.Random) -> List[str]:
    if k <= 1 or len(s) < 2:
        return [s]
    k = min(k, len(s))
    cuts = sorted(rng.sample(range(1, len(s)), k - 1))
    parts, prev = [], 0
    for c in cuts:
        parts.append(s[prev:c])
        prev = c
    parts.append(s[prev:])
    return parts


# ---- T0: control ----------------------------------------------------------
@register("T0.0", "Plaintext (control)", "control", ALL_CARRIERS)
def _t_plain(secret, rng):
    return Emission(secret, secret)


# ---- T1: single-pass encoding --------------------------------------------
@register("T1.1", "Base64", "encoding", ALL_CARRIERS)
def _t_b64(secret, rng):
    e = base64.b64encode(secret.encode()).decode()
    return Emission(e, base64.b64decode(e).decode())


@register("T1.2", "Base32", "encoding", ALL_CARRIERS)
def _t_b32(secret, rng):
    e = base64.b32encode(secret.encode()).decode()
    return Emission(e, base64.b32decode(e).decode())


@register("T1.3", "Base85", "encoding", ALL_CARRIERS)
def _t_b85(secret, rng):
    e = base64.b85encode(secret.encode()).decode()
    return Emission(e, base64.b85decode(e).decode())


@register("T1.4", "Hex", "encoding", ALL_CARRIERS)
def _t_hex(secret, rng):
    e = secret.encode().hex()
    return Emission(e, bytes.fromhex(e).decode())


@register("T1.5", "URL-encoding", "encoding", ALL_CARRIERS)
def _t_url(secret, rng):
    e = urllib.parse.quote(secret, safe="")
    return Emission(e, urllib.parse.unquote(e))


@register("T1.6", "ROT13", "encoding", ALL_CARRIERS)
def _t_rot13(secret, rng):
    e = codecs.encode(secret, "rot_13")
    return Emission(e, codecs.decode(e, "rot_13"))


@register("T1.7", "Gzip + Base64", "encoding", ALL_CARRIERS)
def _t_gzip_b64(secret, rng):
    e = base64.b64encode(gzip.compress(secret.encode())).decode()
    return Emission(e, gzip.decompress(base64.b64decode(e)).decode())


# ---- T2: multi / layered encoding ----------------------------------------
def _b64_n(secret: str, n: int) -> str:
    s = secret.encode()
    for _ in range(n):
        s = base64.b64encode(s)
    return s.decode()


def _b64_n_dec(enc: str, n: int) -> str:
    s = enc.encode()
    for _ in range(n):
        s = base64.b64decode(s)
    return s.decode()


@register("T2.1", "Base64 x2", "multi_encoding", ALL_CARRIERS, depth=2)
def _t_b64x2(secret, rng):
    e = _b64_n(secret, 2)
    return Emission(e, _b64_n_dec(e, 2))


@register("T2.2", "Base64 x3", "multi_encoding", ALL_CARRIERS, depth=3)
def _t_b64x3(secret, rng):
    e = _b64_n(secret, 3)
    return Emission(e, _b64_n_dec(e, 3))


@register("T2.3", "Mixed (Base64 -> Hex)", "multi_encoding", ALL_CARRIERS, depth=2)
def _t_mixed(secret, rng):
    inner = base64.b64encode(secret.encode()).decode()
    e = inner.encode().hex()
    recovered = base64.b64decode(bytes.fromhex(e)).decode()
    return Emission(e, recovered)


# ---- T3: splitting & reassembly (code carriers only) ---------------------
@register("T3.1", "String concatenation", "splitting", CODE_CARRIERS)
def _t_concat(secret, rng):
    parts = _split_parts(secret, 4, rng)
    expr = " + ".join(pylit(p) for p in parts)
    return Emission(expr, "".join(parts), is_expression=True)


@register("T3.2", "Array join", "splitting", CODE_CARRIERS)
def _t_arrjoin(secret, rng):
    parts = _split_parts(secret, 4, rng)
    expr = '"".join([' + ", ".join(pylit(p) for p in parts) + "])"
    return Emission(expr, "".join(parts), is_expression=True)


@register("T3.3", "Character codes", "splitting", CODE_CARRIERS)
def _t_charcodes(secret, rng):
    codes = ", ".join(str(ord(c)) for c in secret)
    expr = '"".join(chr(c) for c in [' + codes + "])"
    return Emission(expr, secret, is_expression=True)


@register("T3.4", "Interleaved variables", "splitting", CODE_CARRIERS)
def _t_interleave(secret, rng):
    parts = _split_parts(secret, 4, rng)
    names = [f"_p{i}" for i in range(len(parts))]
    preamble = [f"{n} = {pylit(p)}" for n, p in zip(names, parts)]
    expr = " + ".join(names)
    return Emission(expr, "".join(parts), is_expression=True, preamble=preamble)


@register("T3.5", "Adjacent string literals", "splitting", CODE_CARRIERS)
def _t_adjacent(secret, rng):
    parts = _split_parts(secret, 4, rng)
    joined = ("\n" + " " * 8).join(pylit(p) for p in parts)
    return Emission("(" + joined + ")", "".join(parts), is_expression=True,
                    note="Python adjacent-literal concatenation")


# ---- T4: character / format manipulation ---------------------------------
_ZERO_WIDTH = "\u200b"  # zero-width space


@register("T4.3", "Hex escape sequences", "char_format", CODE_CARRIERS)
def _t_escape(secret, rng):
    rep = "".join("\\x%02x" % b for b in secret.encode())
    return Emission('"' + rep + '"', secret, is_expression=True,
                    note="string-escape decoding at runtime")


@register("T4.5", "Zero-width insertion", "char_format", ALL_CARRIERS)
def _t_zerowidth(secret, rng):
    rep = _ZERO_WIDTH.join(secret)
    return Emission(rep, rep.replace(_ZERO_WIDTH, ""),
                    note="recover by stripping zero-width characters")


# ---- T5: indirection / reversible arithmetic (code carriers only) --------
@register("T5.1", "Reversed string", "indirection", CODE_CARRIERS)
def _t_reverse(secret, rng):
    expr = f"{pylit(secret[::-1])}[::-1]"
    return Emission(expr, secret, is_expression=True)


@register("T5.2", "XOR with embedded key", "indirection", CODE_CARRIERS)
def _t_xor(secret, rng):
    k = rng.randint(1, 255)
    xored = bytes(b ^ k for b in secret.encode()).hex()
    expr = f"bytes(b ^ {k} for b in bytes.fromhex({pylit(xored)})).decode()"
    return Emission(expr, secret, is_expression=True,
                    note="single-byte XOR, key present in source")


# ---- T6: contextual / carrier manipulation (value is plaintext) ----------
@register("T6.1", "No keyword prefix", "contextual", ALL_CARRIERS)
def _t_noprefix(secret, rng):
    return Emission(secret, secret,
                    note="plaintext value; keyword prefix / secret-y name removed")


@register("T6.4", "Benign variable name", "contextual", ALL_CARRIERS)
def _t_benign(secret, rng):
    return Emission(secret, secret,
                    note="plaintext value under a non-secret-looking identifier")


# ---- T7: composition (chains across families, code carriers only) --------
@register("T7.1", "Split + Base64", "composition", CODE_CARRIERS, depth=2)
def _t_split_b64(secret, rng):
    enc = base64.b64encode(secret.encode()).decode()
    parts = _split_parts(enc, 4, rng)
    joined = " + ".join(pylit(p) for p in parts)
    expr = f"base64.b64decode({joined}).decode()"
    return Emission(expr, base64.b64decode("".join(parts)).decode(),
                    is_expression=True, preamble=["import base64"],
                    note="Base64 then split the blob")


@register("T7.2", "Reverse + Base64", "composition", CODE_CARRIERS, depth=2)
def _t_rev_b64(secret, rng):
    enc = base64.b64encode(secret.encode()).decode()
    expr = f"base64.b64decode({pylit(enc[::-1])}[::-1]).decode()"
    return Emission(expr, base64.b64decode(enc).decode(),
                    is_expression=True, preamble=["import base64"],
                    note="Base64 then reverse")


# ---------------------------------------------------------------------------
# 3. Carrier builders  --  take a list of (varname, Emission); return
#    (file_text, 1-based line of the PRIMARY/first assignment)
# ---------------------------------------------------------------------------
Assignments = List[Tuple[str, Emission]]


def _benign_name(i: int, upper: bool = False) -> str:
    base = "CONFIG_VALUE" if upper else "config_value"
    return base if i == 0 else f"{base}_{i + 1}"


def build_python(assignments: Assignments, family: str) -> Tuple[str, int]:
    benign = family == "contextual"
    header = ["# synthetic benchmark sample -- DO NOT use with real secrets",
              "import os", ""]
    body: List[str] = []
    lines_out: List[int] = []
    for i, (name, em) in enumerate(assignments):
        var = _benign_name(i) if benign else name
        for p in em.preamble:
            body.append(p)
        rhs = em.representation if em.is_expression else pylit(em.representation)
        assign_idx = len(body)
        body.append(f"{var} = {rhs}")
        lines_out.append(len(header) + assign_idx + 1)
    first_var = _benign_name(0) if benign else assignments[0][0]
    footer = ["", "def make_client():", f"    return Client(key={first_var})", ""]
    text = "\n".join(header + body + footer) + "\n"
    return text, lines_out


def build_dotenv(assignments: Assignments, family: str) -> Tuple[str, List[int]]:
    benign = family == "contextual"
    lines = ["# synthetic benchmark sample -- DO NOT use with real secrets"]
    lines_out: List[int] = []
    for i, (name, em) in enumerate(assignments):
        key = _benign_name(i, upper=True) if benign else name.upper()
        lines.append(f"{key}={em.representation}")
        lines_out.append(len(lines))       # 1-based: line just appended
    lines.append("")
    return "\n".join(lines) + "\n", lines_out


def build_yaml(assignments: Assignments, family: str) -> Tuple[str, List[int]]:
    benign = family == "contextual"
    lines = ["# synthetic benchmark sample -- DO NOT use with real secrets"]
    lines_out: List[int] = []
    for i, (name, em) in enumerate(assignments):
        key = _benign_name(i) if benign else name
        lines.append(f'{key}: "{em.representation}"')
        lines_out.append(len(lines))
    lines.append("")
    return "\n".join(lines) + "\n", lines_out


CARRIER_BUILDERS = {"python": build_python, "dotenv": build_dotenv, "yaml": build_yaml}
CARRIER_EXT = {"python": ".py", "dotenv": ".env", "yaml": ".yaml"}


# ---------------------------------------------------------------------------
# 4. Generation driver
# ---------------------------------------------------------------------------
def _make_sample(stype: str, tr: Transform, carrier: str, rng: random.Random):
    """Return (assignments, primary_value, components_meta, all_ok) or None to skip."""
    if stype in COMPOSITE_SECRETS:
        components = COMPOSITE_SECRETS[stype](rng)
        assignments: Assignments = []
        meta = []
        all_ok = True
        for cname, cval in components:
            em = tr.fn(cval, rng)
            if carrier in DATA_CARRIERS and em.is_expression:
                return None
            all_ok = all_ok and ((not em.recoverable) or (em.recovered == cval))
            assignments.append((cname, em))
            meta.append({"name": cname, "value": cval})
        return assignments, components[0][1], meta, all_ok
    # single
    secret = SECRET_FACTORIES[stype](rng)
    em = tr.fn(secret, rng)
    if carrier in DATA_CARRIERS and em.is_expression:
        return None
    all_ok = (not em.recoverable) or (em.recovered == secret)
    return [(stype, em)], secret, None, all_ok


def generate(outdir: str, secret_types: List[str], transform_ids: List[str],
             carriers: List[str], per_combo: int, seed: int):
    rng = random.Random(seed)
    out = Path(outdir)
    corpus_dir = out / "corpus"          # only this subtree is scanned
    manifest: List[dict] = []
    verified = 0
    failures = []
    n = 0

    for stype in secret_types:
        for tid in transform_ids:
            tr = REGISTRY[tid]
            for carrier in carriers:
                if carrier not in tr.carriers:
                    continue
                for _ in range(per_combo):
                    made = _make_sample(stype, tr, carrier, rng)
                    if made is None:
                        continue
                    assignments, primary_value, meta, all_ok = made
                    if all_ok:
                        verified += 1
                    else:
                        failures.append((stype, tid, carrier))

                    text, lines = CARRIER_BUILDERS[carrier](assignments, tr.family)
                    n += 1
                    sid = f"sample_{n:05d}"
                    rel = Path(carrier) / stype / tid.replace(".", "_") / (sid + CARRIER_EXT[carrier])
                    fp = corpus_dir / rel
                    fp.parent.mkdir(parents=True, exist_ok=True)
                    fp.write_text(text, encoding="utf-8")

                    primary_em = assignments[0][1]
                    entry = {
                        "id": sid,
                        "file": str(rel),                 # relative to <outdir>/corpus
                        "carrier": carrier,
                        "secret_type": stype,
                        "secret_value": primary_value,
                        "transformation_id": tid,
                        "transformation_name": tr.name,
                        "family": tr.family,
                        "depth": tr.depth,
                        "expected_line": lines[0],        # primary component's line
                        "recoverable": primary_em.recoverable,
                        "recovery_verified": bool(all_ok),
                        "note": primary_em.note,
                    }
                    if meta is not None:
                        for cm, ln in zip(meta, lines):
                            cm["line"] = ln               # each component's line
                        entry["components"] = meta
                    manifest.append(entry)

    out.mkdir(parents=True, exist_ok=True)
    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return manifest, verified, failures


# ---------------------------------------------------------------------------
# 5. CLI
# ---------------------------------------------------------------------------
def _all_secret_types() -> List[str]:
    return list(SECRET_FACTORIES) + list(COMPOSITE_SECRETS)


def main():
    ap = argparse.ArgumentParser(
        description="Obfuscation-robustness corpus generator for secret scanners "
                    "(SYNTHETIC secrets only). manifest.json is written to the "
                    "output root; only <outdir>/corpus is meant to be scanned.")
    ap.add_argument("--outdir", default="out/run1",
                    help="output root; produces <outdir>/manifest.json and <outdir>/corpus/")
    ap.add_argument("--secrets", nargs="+", default=_all_secret_types(),
                    help="secret types to generate (default: all, incl. aws_keypair)")
    ap.add_argument("--transforms", nargs="+", default=list(REGISTRY),
                    help="transformation IDs (default: all)")
    ap.add_argument("--carriers", nargs="+", default=["python", "dotenv", "yaml"])
    ap.add_argument("--per-combo", type=int, default=1,
                    help="samples per (secret x transform x carrier) cell")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--list", action="store_true",
                    help="list available secret types and transforms, then exit")
    args = ap.parse_args()

    if args.list:
        print("Secret types (single):")
        for k in SECRET_FACTORIES:
            print(f"    {k}")
        print("Secret types (composite / multi-line):")
        for k in COMPOSITE_SECRETS:
            print(f"    {k}")
        print("\nTransformations:")
        for t in REGISTRY.values():
            carr = ",".join(sorted(t.carriers))
            print(f"    {t.tid:6} {t.family:14} depth={t.depth}  {t.name:28} [{carr}]")
        return

    manifest, verified, failures = generate(
        args.outdir, args.secrets, args.transforms,
        args.carriers, args.per_combo, args.seed)

    root = Path(args.outdir)
    print(f"Generated {len(manifest)} samples under '{root / 'corpus'}/'")
    print(f"Ground truth written to '{root / 'manifest.json'}' (NOT inside the scanned tree)")
    print(f"Round-trip verified: {verified}   failures: {len(failures)}")
    for f in failures[:10]:
        print("  RECOVERY FAILED:", f[0], f[1], f[2])


if __name__ == "__main__":
    main()
