#!/usr/bin/env python3
"""build_corpus.py — derive corpus.json from the committed fixtures.

The corpus is GENERATED, not hand-written, so the published criteria cannot drift
from the fixtures that actually produce the verdicts. Re-run and diff to verify.
"""
import hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")


def sha(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


FRONT_MATTER = {
  "publisher": "Hive Life Haven Inc. - federally incorporated non-profit (Canada NFP Act), corp no. 1661181-8. Not a registered charity; no charitable claim is made.",
  "licence": {"code": "Apache-2.0", "docs": "CC-BY-4.0", "fixtures_and_expected_verdicts": "CC0-1.0"},
  "certifies_nothing": "This corpus publishes criteria and expected verdicts. It is not a certification, not a mark, not an accreditation, and not an assurance opinion.",
  "no_warranty": "Provided AS IS, without warranty of any kind, express or implied, including merchantability, fitness for a particular purpose and non-infringement.",
  "no_reliance": "No reliance may be placed on this corpus as an assurance opinion or as evidence of any third party's conformance.",
  "no_endorsement": "Use of these criteria, or of a verdict produced by them, does not imply endorsement by, affiliation with, or approval of the publisher. No trademark licence is granted; the publisher's name and any mark may not be used to advertise a product as passing Hive criteria without written permission.",
  "version": "0.2.0",
  "immutability": "A published release is immutable. Any change to an arm, fixture or expected verdict requires a new version; superseded versions stay available at their pinned digest.",
  "errata_permalink_rule": "Errata are published as a dated permalink beside the affected release; the release itself is never edited in place.",
  "public_surface": "unpublished - see CORPUS-v0.md section 6; A1 is MET only when an unauthenticated fetch from a non-author box of a pinned digest returns these bytes plus this licence and front-matter, recorded as a dated permalink + sha256."
}


def build():
    man = json.loads(open(os.path.join(FIX, "cases.json")).read())
    arms = []
    for i, c in enumerate(man["cases"], 1):
        entry = {
            "id": f"CV-{i:02d}",
            "subject": c["name"],
            "input": {
                "card": c["card"],
                "card_sha256": sha(os.path.join(FIX, c["card"])),
                "form": c.get("form", "json"),
                "anchor": c["anchor"],
                "anchor_sha256": sha(os.path.join(FIX, c["anchor"])),
                "jwks": c.get("jwks"),
            },
            "expected_verdict": c["expect"],
        }
        if c.get("jwks"):
            entry["input"]["jwks_sha256"] = sha(os.path.join(FIX, c["jwks"]))
        arms.append(entry)
    return {
        "front_matter": FRONT_MATTER,
        "corpus": "card-verify",
        "version": "0.2.0",
        "subject": "card / identity-assertion verification (NOT authority-adherence)",
        "generated_from": "fixtures/cases.json",
        "generator": "build_corpus.py",
        "arm_count": len(arms),
        "arms": arms,
    }


if __name__ == "__main__":
    doc = build()
    out = os.path.join(HERE, "corpus.json")
    text = json.dumps(doc, indent=2) + "\n"
    if "--check" in sys.argv:
        cur = open(out).read() if os.path.exists(out) else ""
        if cur != text:
            print("DRIFT: corpus.json does not match the fixtures"); raise SystemExit(1)
        print(f"OK: corpus.json matches the fixtures ({doc['arm_count']} arms)")
        raise SystemExit(0)
    open(out, "w").write(text)
    print(f"wrote corpus.json — {doc['arm_count']} arms")
