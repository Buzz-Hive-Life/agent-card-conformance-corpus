#!/usr/bin/env python3
"""verify_fixture.py — the SEEDLESS receipt: an outside verifier with no shared state checks the card.

Runs with ZERO Hive state: it reads only this directory's committed `fixtures/`
(card blobs + anchors + a manifest) and calls verify_card.verify(). It touches
NO Hive key material, NO seed material, and holds no private key. This — not the mint
harness — is the run that demonstrates:

  "an outside verifier holding zero Hive table verifies our card."

Reproduce on any box:
    python3 verify_fixture.py          # exit 0 = every arm classified as expected
Works without `cryptography` (the fleet's hive_ed25519 stdlib fallback is used),
so a box that runs bare `python3` can produce this receipt.

Layout: reads `./fixtures/` beside this script by default; set `CARD_FIXTURES_DIR`
for a flat copy, and `CARD_JCS_DIR` / `HIVE_ED25519_DIR` if the two consumed
primitives are not in the repo layout.
"""
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from verify_card import verify, verify_bytes, backend  # noqa: E402

# Default: a `fixtures/` dir beside this script (the repo layout). For a FLAT
# copy of the published blobs, point CARD_FIXTURES_DIR at wherever they landed —
# otherwise this script hard-requires the `fixtures/` subdir.
FIX = os.environ.get("CARD_FIXTURES_DIR") or os.path.join(_HERE, "fixtures")


def _load(name):
    with open(os.path.join(FIX, name)) as f:
        return f.read()


def main() -> int:
    man = json.loads(_load("cases.json"))
    print(f"agent   : {man['agent']}   kid: {man['kid']}")
    print(f"backend : {backend()}   (Ed25519 via the fleet's hive_ed25519)")
    print("state   : fixtures-only — no key material, no seed material, no private key")
    print()
    ok = 0
    framing_ok = 0
    for c in man["cases"]:
        jwks = json.loads(_load(c["jwks"])) if c.get("jwks") else None
        anchor = _load(c["anchor"])
        if c.get("form") == "raw":
            with open(os.path.join(FIX, c["card"]), "rb") as f:
                res = verify_bytes(f.read(), anchor, jwks)
        else:
            res = verify(json.loads(_load(c["card"])), jwks, anchor)
        got = res["verdict"]
        # machine-checked FRAMING RULE: no verdict may select a remedy
        framing_ok += (res.get("actionable") is False) and (
            got != "anchor_stale" or res.get("advisory_only") is True)
        good = got == c["expect"]
        ok += good
        print(f"[{'OK  ' if good else 'FAIL'}] want={c['expect']:24s} got={got:24s} {c['name']}")
    print(f"\n{ok}/{len(man['cases'])} arms as expected")
    print(f"framing rule (no verdict actionable; anchor_stale advisory-only): "
          f"{framing_ok}/{len(man['cases'])}")
    return 0 if ok == len(man["cases"]) and framing_ok == len(man["cases"]) else 1


if __name__ == "__main__":
    sys.exit(main())
