#!/usr/bin/env python3
"""verify_oracle.py — the EXTERNAL oracle for the card-verify corpus.

Every other check in this directory compares our instrument against OUR OWN
authored expectations. This one compares it against references authored by
parties with no relationship to the Hive, so "the verdict is reproducible" is
raised to "the verdict is reproducible AND correct against an external
reference".

Two legs, both run inside the same instrument:

  LEG A · RFC 8032 §7.1 (Ed25519) — the vendored fleet primitive must:
     A1  derive the RFC's public key from the RFC's secret seed
     A2  verify the RFC's signature over the RFC's message
     A3  reproduce the RFC's signature deterministically (sign is deterministic)
     N1  NEGATIVE: a one-byte message mutation must FAIL verification
     N2  NEGATIVE: a one-byte signature mutation must FAIL verification

  LEG B · RFC 8785 (JCS) — the corpus's consumed canonicalizer must reproduce
     the reference implementation's published canonical output BYTE-FOR-BYTE.
     N3  NEGATIVE: a mutated input must NOT produce the reference output.

Exit 0 iff every arm passes. Prints one receipt line per arm.

Zero Hive state: reads only the committed files beside it.
"""
import hashlib
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))


def _locate(name, *cands):
    for c in cands:
        if c and os.path.isfile(os.path.join(c, name)):
            return c
    return None


HE_DIR = _locate("hive_ed25519.py",
                 os.environ.get("HIVE_ED25519_DIR"),
                 os.path.join(_HERE, os.pardir, os.pardir, "scripts"),   # release layout
                 os.path.join(_HERE, os.pardir, "scripts"),
                 os.path.join(_HERE, "..", "..", "..", "..", "scripts"),  # repo layout
                 os.path.join(_HERE, "..", "..", "..", "..", "..", "scripts"))
JCS_DIR = _locate("card_jcs_battery.py",
                  os.environ.get("CARD_JCS_DIR"),
                  os.path.join(_HERE, "..", "..", "card-jcs-battery"),
                  os.path.join(_HERE, "..", "card-jcs-battery"))
if not HE_DIR:
    raise SystemExit("hive_ed25519.py not found (set HIVE_ED25519_DIR)")
if not JCS_DIR:
    raise SystemExit("card_jcs_battery.py not found (set CARD_JCS_DIR)")
sys.path.insert(0, HE_DIR)
sys.path.insert(0, JCS_DIR)
import hive_ed25519                                        # noqa: E402
from card_jcs_battery import jcs_bytes                      # noqa: E402


def flip(b: bytes, pos: int = 0) -> bytes:
    return b[:pos] + bytes([b[pos] ^ 0x01]) + b[pos + 1:]


def main() -> int:
    results = []
    vec_doc = json.load(open(os.path.join(_HERE, "rfc8032_ed25519.json")))
    src = vec_doc["source"]
    print(f"oracle    : RFC 8032 (§7.1) + RFC 8785 (JCS reference testdata)")
    print(f"ed25519   : {getattr(hive_ed25519, 'BACKEND', 'n/a')}")
    print(f"source    : {src['url']}  fetched {src['fetched']}")
    print()

    for name, v in vec_doc["vectors"].items():
        seed = bytes.fromhex(v["secret"])
        pub = bytes.fromhex(v["public"])
        msg = bytes.fromhex(v["message"])
        sig = bytes.fromhex(v["signature"])

        a1 = hive_ed25519.public_from_seed(seed) == pub
        a2 = hive_ed25519.verify(pub, sig, msg) is True
        a3 = hive_ed25519.sign(seed, msg) == sig
        n1 = hive_ed25519.verify(pub, sig, flip(msg) if msg else b"\x00") is False
        n2 = hive_ed25519.verify(pub, flip(sig), msg) is False
        results += [(f"A1 {name} pubkey ", a1), (f"A2 {name} verify ", a2),
                    (f"A3 {name} sign   ", a3), (f"N1 {name} msg-mut", n1),
                    (f"N2 {name} sig-mut", n2)]

    jdir = os.path.join(_HERE, "rfc8785_jcs")
    for case in ("arrays", "french"):
        raw = open(os.path.join(jdir, f"input_{case}.json"), "rb").read()
        want = open(os.path.join(jdir, f"output_{case}.json"), "rb").read().rstrip(b"\n")
        got = jcs_bytes(json.loads(raw.decode("utf-8")))
        results.append((f"B  jcs {case} canonical", got.rstrip(b"\n") == want))
        # N3: a mutated input must not reproduce the reference output
        try:
            mutated = json.loads(raw.decode("utf-8"))
            if isinstance(mutated, list):
                mutated = mutated + ["zz-mut"]
            else:
                mutated["zz-mut"] = 1
            results.append((f"N3 jcs {case} mutated  ",
                            jcs_bytes(mutated).rstrip(b"\n") != want))
        except Exception:                                   # noqa: BLE001
            results.append((f"N3 jcs {case} mutated  ", False))

    ok = 0
    for label, passed in results:
        print(f"  [{'PASS' if passed else 'FAIL'}] {label}")
        ok += bool(passed)
    print()
    print(f"arms: {ok}/{len(results)}   exit {0 if ok == len(results) else 1}")
    return 0 if ok == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
