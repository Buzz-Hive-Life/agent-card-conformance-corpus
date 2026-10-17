# CORPUS-v0 — card-verify (published criteria corpus)

**Corpus:** `card-verify` · **version** `0.2.0` · **arms** `13`
**Subject (stated plainly):** card / identity-assertion verification — **not** deployed-agent authority-adherence. This is the instrument's *reproducibility demonstration*; the authority-adherence corpus is a separate, net-new build.
**Machine-readable form:** `corpus.json` — **generated** from `fixtures/cases.json` by `build_corpus.py`, so the published criteria cannot drift from the fixtures that produce the verdicts. Re-derive and compare: `python3 build_corpus.py --check`.

---

## 1 · Publication front-matter — **signed** (counsel read, 2026-10-15)

These fields were reviewed and signed by counsel on 2026-10-15, with the licence split below as the one condition carried to the public push.

- **Publisher:** Hive Life Haven Inc. — federally incorporated non-profit (Canada NFP Act), corp no. **1661181-8**. *We are **not** a registered charity and make no charitable claim.*
- **Licence:** split by artifact class — source **Apache-2.0** · prose **CC-BY-4.0** · fixtures **CC0-1.0**; full canonical texts vendored in `LICENSE-CODE` / `LICENSE-DOCS` / `LICENSE-FIXTURES`.
- **Name use:** the corpus is published under the registered name above and no other. It is **not** affiliated with, endorsed by, or a member of any standards body or incumbent named in the accompanying matrix.
- **What this is not:** **the corpus certifies nothing.** It publishes criteria and expected verdicts. There is no certification, no mark, no accreditation, and no assurance of any third party's product. **No reliance** may be placed on it as an assurance opinion.
- **No private benefit:** publication is free; nothing here confers a benefit on a member or director.

## 2 · The arms

Every arm names its input, the sha256 of that input, and the verdict it must produce.

| ID | Subject | Card | card sha256 | Expected verdict |
|---|---|---|---|---|
| CV-01 | positive control — tamper-free JCS card | `card_pass.json` | `f3a56024403195ae…` | `pass` |
| CV-02 | format_drift — signed over HOUSE bytes | `card_drift.json` | `56e232254ba7817a…` | `format_drift` |
| CV-03 | key_mismatch — valid sig under the anchor, foreign kid declared | `card_kid_mismatch.json` | `8626d5ae0c680846…` | `key_mismatch` |
| CV-04 | signature_invalid — kid==fp, a field mutated after signing | `card_tampered.json` | `9d129a84394910d2…` | `signature_invalid` |
| CV-05 | jwks repointed — discovery disagrees with anchor | `card_pass.json` | `f3a56024403195ae…` | `jwks_anchor_mismatch` |
| CV-06 | axis-3 — non-ASCII card KEY | `card_nonascii_key.json` | `466fb55a7eebe66b…` | `refused_nonascii_key` |
| CV-07 | axis-2 — float in the card | `card_float.json` | `8da898de2a0d2892…` | `refused_float` |
| CV-08 | axis-2 — int beyond JCS-exact range (|n| >= 2^53) | `card_big_int.json` | `91ac138c2cc22d9e…` | `refused_int_range` |
| CV-09 | anchor_stale — kid!=fp and sig fails (rotation vs forged kid: indistinguishable locally) | `card_pass.json` | `f3a56024403195ae…` | `anchor_stale` |
| CV-10 | no_pinned_anchor — no anchor supplied (discovery must not fill in) | `card_pass.json` | `f3a56024403195ae…` | `no_pinned_anchor` |
| CV-11 | ORDERING — hostile not_after must not rescue a bad signature | `card_tampered_expiry.json` | `b9ccaa7f6fec8bdb…` | `signature_invalid` |
| CV-12 | JWS compact — signature over the EXACT received bytes | `card_jws_compact.txt` | `1ecaa418cf5b828d…` | `pass` |
| CV-13 | JWS compact — wire-mutated payload (parsed-equal) is REJECTED | `card_jws_wire_mutated.txt` | `b37efd3f320516ae…` | `signature_invalid` |

## 3 · How a stranger reproduces a verdict

```sh
# from this directory (docs/peer-lane/card-verify):
python3 verify_fixture.py            # seedless: reads only ./fixtures, zero Hive state
# from the oracle subdirectory:
cd oracle && python3 verify_oracle.py   # binds the instrument to EXTERNAL references
```
- **`verify_fixture.py`** — no private key, no key material, no seed material, no membership, no shared table. Expected on a bare `python3`: `13/13 arms · framing 13/13 · exit 0`.
- **`verify_oracle.py`** — the **external** leg: RFC 8032 §7.1 (5 published Ed25519 vectors) and RFC 8785 JCS reference testdata, with positive **and negative** controls in the same instrument. Expected: **29/29 arms · exit 0**.
- **Frozen digest** — the current pin (**rev 3**, content-bound) lives in `VERIFICATION-TARGET.md` with the recompute command; earlier revisions are kept there as *superseded*, so older receipts resolve to their own recipe.

## 4 · Substantiation

| Claim this corpus makes | Basis |
|---|---|
| per-test criteria + expected verdicts are published | this file + `corpus.json`, generated from `fixtures/cases.json` |
| a stranger reproduces the verdict from published bytes | `verify_fixture.py`, discharged on non-author volumes |
| verdicts are correct against an **external** reference, not just internally consistent | `verify_oracle.py` — RFC 8032 §7.1 + RFC 8785 |
| the *subject* is card/identity-assertion verification | arm table above; the one-axis differentiator subject is explicitly **out of scope here** |

**No "first" or superiority claim is made in this document.** The competitive position lives in `docs/AGENT-IDENTITY-INCUMBENT-MATRIX.md` (14 rows, evidence-tiered) and is not asserted here.

## 5 · Fixture audit — basis, not conclusion

**Basis.** Every file under `fixtures/` was read byte-for-byte and scanned for: email addresses, phone numbers, URLs, individual names, key material and seed material. Method: regex sweep over each file's bytes + manual read of the payload fields of all 15 fixtures.

**Result.** No personal information is present. The payload actor strings are now **neutral** — `agent: test-agent` · `display: 🧪 Example Agent` · `role: Example Agent Role` · `iss: example.com`. `example.com` is a **reserved name (RFC 2606 / RFC 6761)**; it resolves to no live host and identifies no real party, so a published card can no longer present a real domain as the issuer of a signed assertion.

**Signing material.** The fixtures are signed with a key DERIVED from a published label (`build_corpus.py` / `mint_fixtures.py` -> `_test_seed`), so any stranger can re-mint this fixture set byte-for-byte and confirm it signs nothing real. **No fleet key and no internal filesystem path appears in the corpus** — the mint script resolves every input from the published label and reads no key store, seed directory, or host path.

**Version-pin (v0.2.0).** The fixture set is pinned by a content-bound digest:

> `FIXTURES_DIGEST (fixtures/) = b7047da6b065a0f4c6877c972d086d4d1fcb076b9a9f00fbecb545dc3127c16d`  — sha256 of the sorted `sha256sum` lines, each reduced to `<full-hash>  <basename>`, sorted by the whole line (the rev-2 reduction). **A change to any fixture is a new version with a new declared hash.**

**What changed from v0.1.0:** the payload actor strings (real -> reserved/neutral), the signing key (fleet -> published test seed), and the removal of Hive paths from the mint script. The 13 arms and their expected verdicts are unchanged; `verify_fixture.py` reports **13/13**, `verify_oracle.py` **29/29**.

## 6 · Status

This release is **published** at the pinned digest declared in `card-verify/VERIFICATION-TARGET.md`
and summarised in `RELEASE-MANIFEST.md`. The corpus digest binds the 22 named files; the release
digest binds everything else that ships (licences, front-matter, landing page, oracle vectors).

The frozen pin and the release pin are both declared, so a post-publication edit to a licence, the
front-matter or the oracle is detectable. **A1 is met when an unauthenticated fetch from a non-author
box of the pinned digest returns these bytes plus this licence and front-matter, recorded as a dated
permalink + sha256.**
