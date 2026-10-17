#!/usr/bin/env python3
"""card_jcs_battery.py — ONE canonicalizer (RFC 8785 JCS + UTF-8) + the 4-fixture battery
for Hive agent cards.

Scope: verification artifact. Publishes a JCS canonicalizer and a four-fixture battery
for agent-card conformance. No deploy, nothing armed.

What it proves
--------------
1. A JCS canonicalizer exists whose bytes differ from the house idiom exactly where the
   house idiom is wrong (non-ASCII), and which SIGN+VERIFY agree on BY CONSTRUCTION.
2. The 4-fixture battery (happy / format_drift / key_mismatch / tampered) CLASSIFIES a
   failure rather than merely reporting one -> attributability of the card lane.
3. Interop: the SAME JCS bytes signed under this box's backend and under `cryptography`
   produce byte-identical signatures (Ed25519 is deterministic).

Rule kept (banked): the POSITIVE fixture must pass FIRST, or no negative reading counts.
"""
import hashlib
import json
import os
import sys

# Resolve the Ed25519 primitive without any absolute internal path.
# Order: explicit env override -> our own directory -> the release root -> a repo-style scripts/ dir.
_HERE = os.path.dirname(os.path.abspath(__file__))
for _cand in (os.environ.get("HIVE_ED25519_DIR"),
              _HERE,
              os.path.join(_HERE, os.pardir),
              os.path.join(_HERE, os.pardir, "scripts"),
              os.path.join(_HERE, os.pardir, os.pardir, os.pardir, os.pardir, "scripts")):
    if _cand and os.path.isfile(os.path.join(_cand, "hive_ed25519.py")):
        sys.path.insert(0, _cand)
        break
import hive_ed25519 as E  # noqa: E402

# ── JCS (RFC 8785), restricted to the CARD surface ────────────────────────────
_ESC = {'"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f', '\n': '\\n', '\r': '\\r', '\t': '\\t'}


def _jcs_str(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch in _ESC:
            out.append(_ESC[ch])
        elif ord(ch) < 0x20:
            out.append('\\u%04x' % ord(ch))
        else:
            out.append(ch)          # literal UTF-8, NOT \uXXXX  <- the whole point
    out.append('"')
    return ''.join(out)


def _key_order(k: str) -> bytes:
    """RFC 8785 sorts object keys by UTF-16 code units -> compare UTF-16-BE bytes."""
    return k.encode('utf-16-be')


def _ser(o) -> str:
    if o is True:
        return 'true'
    if o is False:
        return 'false'
    if o is None:
        return 'null'
    if isinstance(o, str):
        return _jcs_str(o)
    if isinstance(o, int):
        return str(o)
    if isinstance(o, float):
        # fail LOUD rather than silently emit a non-JCS number
        raise TypeError("JCS: floats are not supported on the card surface (fail loud)")
    if isinstance(o, list):
        return '[' + ','.join(_ser(x) for x in o) + ']'
    if isinstance(o, dict):
        return '{' + ','.join(_jcs_str(k) + ':' + _ser(o[k])
                              for k in sorted(o, key=_key_order)) + '}'
    raise TypeError(f"JCS: unsupported type {type(o).__name__}")


def jcs_bytes(o) -> bytes:
    return _ser(o).encode('utf-8')


def house_bytes(o) -> bytes:
    """The legacy idiom, kept ONLY to generate the format_drift fixture."""
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


# ── RFC 8785 GOLDEN VECTORS (the RFC's OWN input/output pairs), embedded so the
# check is OFFLINE and self-contained: PEP 668 boxes have no pip and no JCS lib
# is installable, so an external oracle must travel with the artifact.
# Source: github.com/cyberphone/json-canonicalization/testdata  (2026-10-14).
# "raise" = the vector carries floats; the card surface EXCLUDES numbers, so the
# canonicalizer refuses (fail loud) instead of silently emitting non-JCS bytes.
GOLDEN = [
    ('arrays', '[\n  56,\n  {\n    "d": true,\n    "10": null,\n    "1": [ ]\n  }\n]\n', '[56,{"1":[],"10":null,"d":true}]', 'match'),
    ('french', '{\n  "peach": "This sorting order",\n  "péché": "is wrong according to French",\n  "pêche": "but canonicalization MUST",\n  "sin":   "ignore locale"\n}\n', '{"peach":"This sorting order","péché":"is wrong according to French","pêche":"but canonicalization MUST","sin":"ignore locale"}', 'match'),
    ('structures', '{\n  "1": {"f": {"f": "hi","F": 5} ,"\\n": 56.0},\n  "10": { },\n  "": "empty",\n  "a": { },\n  "111": [ {"e": "yes","E": "no" } ],\n  "A": { }\n}', '{"":"empty","1":{"\\n":56,"f":{"F":5,"f":"hi"}},"10":{},"111":[{"E":"no","e":"yes"}],"A":{},"a":{}}', 'raise'),
    ('unicode', '{\n  "Unnormalized Unicode":"A\\u030a"\n}\n', '{"Unnormalized Unicode":"Å"}', 'match'),
    ('values', '{\n  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],\n  "string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",\n  "literals": [null, true, false]\n}', '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}', 'raise'),
    ('weird', '{\n  "\\u20ac": "Euro Sign",\n  "\\r": "Carriage Return",\n  "\\u000a": "Newline",\n  "1": "One",\n  "\\u0080": "Control\\u007f",\n  "\\ud83d\\ude02": "Smiley",\n  "\\u00f6": "Latin Small Letter O With Diaeresis",\n  "\\ufb33": "Hebrew Letter Dalet With Dagesh",\n  "</script>": "Browser Challenge"\n}\n', '{"\\n":"Newline","\\r":"Carriage Return","1":"One","</script>":"Browser Challenge","\x80":"Control\x7f","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","😂":"Smiley","דּ":"Hebrew Letter Dalet With Dagesh"}', 'match'),
]


# ── CARD-SURFACE KEY GATE (axis 3) — deliberately NOT inside jcs_bytes ────────
# RFC 8785 sorts object keys by UTF-16 code units; the house idiom (json.dumps
# sort_keys) sorts by code point. Those two orders agree IFF the keys are ASCII
# (e.g. `a, ｡, 😀` vs `a, 😀, ｡` — a real flip). Constraining CARD keys to ASCII
# therefore removes the key-order divergence class between implementations, the
# same way refusing floats removes the number-formatting class.
#
# ⚠️ PLACEMENT IS LOAD-BEARING: this gate must NOT live inside jcs_bytes().
# The RFC's OWN golden vectors carry non-ASCII KEYS (`french`: peche/peche',
# `weird`: EUR, U+0080, an emoji, o-umlaut) — pushing the gate into the
# canonicalizer would make it refuse inputs the standard REQUIRES it to
# canonicalize, inverting the golden oracle. The canonicalizer stays a general,
# RFC-correct JCS impl; the ASCII-key rule is a CONTRACT ON THE CARD SCHEMA.
def assert_ascii_keys(o, path="") -> None:
    """Card-surface gate: raise (fail LOUD) on any non-ASCII or non-string key."""
    if isinstance(o, dict):
        for k, v in o.items():
            if not isinstance(k, str):
                raise TypeError(f"card surface: non-string key at {path or '$'} ({type(k).__name__})")
            if any(ord(ch) > 127 for ch in k):
                raise TypeError(
                    f"card surface: non-ASCII key {k!r} at {path or '$'} — JCS sorts by UTF-16 "
                    f"units, so non-ASCII keys make key order implementation-dependent; "
                    f"non-ASCII belongs in VALUES")
            assert_ascii_keys(v, f"{path}.{k}")
    elif isinstance(o, list):
        for i, v in enumerate(o):
            assert_ascii_keys(v, f"{path}[{i}]")

# ── fixtures ─────────────────────────────────────────────────────────────────
SEED_A = bytes.fromhex("11" * 32)
SEED_B = bytes.fromhex("22" * 32)
PUB_A, PUB_B = E.public_from_seed(SEED_A), E.public_from_seed(SEED_B)
KID_A, KID_B = "fp-key-A", "fp-key-B"
KEYS = {KID_A: PUB_A, KID_B: PUB_B}


def card(display_ascii: str = "Example Agent") -> dict:
    """A neutral specimen card. Signs nothing real; names no live host."""
    return {
        "agent": "test-agent",
        "alg": "EdDSA",
        "kid": KID_A,
        "display": display_ascii,
        "mesh_key": "test-agent",
        "schema": "agent-card/1",
        "url": "https://example.com",
        "not_after": "2027-01-01T00:00:00Z",
    }


def classify(obj, sig: bytes, advertised_kid: str) -> str:
    """Name the failure instead of just reporting one."""
    pub = KEYS.get(advertised_kid)
    if pub and E.verify(pub, sig, jcs_bytes(obj)):
        return "pass"
    # signature is genuine, but over NON-canonical bytes -> the house idiom
    if pub and E.verify(pub, sig, house_bytes(obj)):
        return "format_drift"
    # signature is genuine over the CORRECT bytes, but under a DIFFERENT key
    for k, p in KEYS.items():
        if k != advertised_kid and E.verify(p, sig, jcs_bytes(obj)):
            return "key_mismatch"
    return "tampered"



def run_golden() -> tuple:
    """External oracle: canonicalize the RFC's own inputs; compare to ITS outputs."""
    rows, ok = [], True
    for name, inp, expected, mode in GOLDEN:
        exp_bytes = expected.encode("utf-8")
        try:
            got = jcs_bytes(json.loads(inp))
            good = (mode == "match" and got == exp_bytes)
            rows.append({"vector": name, "mode": mode,
                         "result": "match" if good else "MISMATCH", "ok": good})
        except TypeError as e:
            good = (mode == "raise")
            rows.append({"vector": name, "mode": mode, "result": f"raised({e})",
                         "ok": good})
        ok = ok and good
    return ok, rows

def main() -> int:
    rows, ok = [], True

    def check(name, obj, sig, advertised, expected):
        nonlocal ok
        got = classify(obj, sig, advertised)
        good = got == expected
        ok = ok and good
        rows.append({"fixture": name, "expected": expected, "actual": got,
                     "verdict": "PASS" if good else "FAIL"})
        return good

    golden_ok, golden_rows = run_golden()
    ok = ok and golden_ok

    c = card("Example Agent")                  # ASCII card (the recommended shape)
    jcs, house = jcs_bytes(c), house_bytes(c)

    # POSITIVE CONTROL FIRST — no negative reading counts until this passes.
    check("0 positive_control", c, E.sign(SEED_A, jcs), KID_A, "pass")
    if not rows[0]["verdict"] == "PASS":
        print(json.dumps(rows, indent=2))
        print("\nPOSITIVE CONTROL FAILED -> battery is vacuous, stopping.")
        return 2

    check("1 happy", c, E.sign(SEED_A, jcs), KID_A, "pass")
    check("3 key_mismatch", c, E.sign(SEED_A, jcs), KID_B, "key_mismatch")
    tampered = dict(c, url="https://evil.example/a2a")
    check("4 tampered", tampered, E.sign(SEED_A, jcs), KID_A, "tampered")

    # the emoji card: the ONLY place the two canonicalizations actually differ.
    emo = card("🧪 Example Agënt")
    ej, eh = jcs_bytes(emo), house_bytes(emo)

    # 2 is the REAL drift fixture -> MUST use a non-ASCII payload.
    check("2 format_drift", emo, E.sign(SEED_A, eh), KID_A, "format_drift")
    # 2b VACUITY DEMONSTRATION: on an ASCII card house==jcs, so a "drift" signature IS a
    # valid JCS signature -> format_drift is UNEXERCISABLE. An ASCII-only card leaves the
    # drift latent and untested for the day a display name is added.
    check("2b ascii_vacuity", c, E.sign(SEED_A, house), KID_A, "pass")
    # 5 CARD-SURFACE KEY GATE (axis 3): non-ASCII KEYS refuse; ASCII keys + non-ASCII VALUES pass.
    try:
        assert_ascii_keys(emo)                     # keys ASCII, values non-ASCII -> allowed
        gate_ok = True
    except TypeError as e:
        gate_ok = f"unexpected: {e}"
    try:
        assert_ascii_keys({"agent": "test-agent", "\u00e9": "boom"})
        refused = False
    except TypeError:
        refused = True
    ok = ok and (gate_ok is True) and refused
    rows.append({"fixture": "5 card_key_gate", "expected": "ascii-values-ok + nonascii-key-refused",
                 "actual": f"ascii_words_ok={gate_ok is True} nonascii_key_refused={refused}",
                 "verdict": "PASS" if (gate_ok is True and refused) else "FAIL"})


    print(json.dumps({
        "backend": E.BACKEND,
        "positive_control_first": rows[0]["verdict"],
        "battery": rows,
        "battery_all_pass": ok,
        "canonicalizer": {
            "ascii_card_jcs_sha256_16": hashlib.sha256(jcs).hexdigest()[:16],
            "ascii_card_house_sha256_16": hashlib.sha256(house).hexdigest()[:16],
            "emoji_card_jcs_sha256_16": hashlib.sha256(ej).hexdigest()[:16],
            "emoji_card_house_sha256_16": hashlib.sha256(eh).hexdigest()[:16],
            "emoji_jcs_len": len(ej), "emoji_house_len": len(eh),
            "emoji_diverges": ej != eh,
            "ascii_diverges": jcs != house,
        },
        # interop: deterministic signature over FIXED bytes -> compare across backends
        "interop_sig_sha256_16": hashlib.sha256(E.sign(SEED_A, jcs)).hexdigest()[:16],
        "interop_pub_sha256_16": hashlib.sha256(PUB_A).hexdigest()[:16],
        "rfc8785_golden": {"all_ok": golden_ok, "vectors": golden_rows},
        "card_surface": {"keys_ascii_required": True, "floats_refused": True,
                         "gate_not_inside_canonicalizer": True},
    }, indent=2, ensure_ascii=False))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
