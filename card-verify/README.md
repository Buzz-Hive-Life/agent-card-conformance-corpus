# Card verifier — specification and reproducible receipt

**Maintainer:** Hive Life Haven Inc. (published corpus) · 2026-10-14
**Status:** verification artifact only — no serving code, nothing deployed.
**Scope:** the verifier half of the publication harness. The canonicalizer + battery
(`../card-jcs-battery/`) are **consumed**, never re-implemented.

| file | role | reads |
|---|---|---|
| `verify_card.py` | verifier **module** | nothing internal; consumes 2 published primitives |
| `mint_fixtures.py` | **signer side** (mint) | a **test seed derived from a published label** — the fixtures sign nothing real |
| `verify_fixture.py` | **seedless receipt** | `fixtures/` only |
| `fixtures/` | committed card blobs + anchors + `cases.json` | — |

Reproduce on any box: `python3 verify_fixture.py` (exit 0 = every arm as expected).
Reads `./fixtures/` beside the script; for a **flat copy** of the published blobs set
`CARD_FIXTURES_DIR`, and `CARD_JCS_DIR` / `HIVE_ED25519_DIR` if the two consumed
primitives aren't in the repo layout.

---

## 1. What this discharges

The claim: **an outside verifier holding no shared table verifies the card.**

The **receipt** (`verify_fixture.py`) holds no seed and no Hive path: it reads only the
committed `fixtures/` and calls `verify_card.verify(card, jwks, anchor_pub_hex)`. The **mint**
(`mint_fixtures.py`) is the only part that touches a private key, and it is a *different role*
— the publisher's. (v1 conflated them: its 8/8 receipt came from a runner that read the
subject's own seed, i.e. an **author self-witness** one level up — caught in review.)

## 2. Two primitives consumed, not re-implemented

- canonicalizer — `../card-jcs-battery/card_jcs_battery.py`
- Ed25519 — `scripts/hive_ed25519.py` (**stdlib RFC 8032 fallback**, so this runs with **no
  `cryptography` installed**)

Both are repo-tracked. The trust anchor is a **parameter**, never a fetch: a served JWKS may
only *confirm* it (`jwks_anchor_mismatch` if it disagrees). Discovery ≠ trust — the outside
counterpart of *"the trust store is pinned: no mesh-facing endpoint may write a trust anchor."*

## 2b. "Verify over the received bytes" — TRUE for JWS compact, NOT for the detached form

Declared ≠ actual, so both forms are named rather than blurred (caught in review):

| form | entry point | signing input | wire-mutated card (parsed-equal) |
|---|---|---|---|
| **JWS compact** (RFC 7515 §7.1) | `verify_bytes()` | the **EXACT received bytes** `header.payload` | **REJECTED** → `signature_invalid` |
| **detached JSON** `{payload, signature}` | `verify()` | `JCS(parsed payload)` | **ACCEPTED** (canonicalizer equality) |

The detached form re-canonicalizes, so its interop rests on *canonicalizer equality* and its
`kid` is a **payload** field. The compact form keeps the canonicalizer **out of the verification
path entirely** and carries `kid` in the **protected header**, which the signature authenticates.
Arms 12–13 pin the difference: same parsed payload, two wire encodings, two verdicts.

## 2c. No verdict may select a remedy

Every refusal here is computed from **unauthenticated** input, so an attacker can influence
*which* refusal is named. Therefore none is actionable: `_finish()` stamps `actionable: False`
on every verdict, and `anchor_stale` is **advisory-only** (`remedy: surface to a human; never
auto re-pin`). A re-pin is a trust-store **write** — a received card's verdict must never
trigger one. Machine-checked: the fixture run asserts this framing rule on every arm.

## 3. Verdicts — a mismatch is NAMEABLE, never a bare "invalid"

| # | arm | expected |
|---|---|---|
| 1 | positive control — tamper-free JCS card | `pass` |
| 2 | signed over **HOUSE** bytes (not JCS) | `format_drift` |
| 3 | card advertises a foreign `kid` | `key_mismatch` |
| 4 | `kid` == fp, a field **mutated after signing** | `signature_invalid` |
| 5 | served JWKS disagrees with the pinned anchor | `jwks_anchor_mismatch` |
| 6 | non-ASCII card **key** (axis-3) | `refused_nonascii_key` |
| 7 | float in the card (axis-2) | `refused_float` |
| 8 | int `abs(n) >= 2^53` — not JCS-exact (axis-2 residual) | `refused_int_range` |
| 9 | `kid` != fp **and** sig fails (rotation vs forged kid) | `anchor_stale` |
| 10 | no anchor supplied (discovery must not fill in) | `no_pinned_anchor` |
| 11 | **ordering** — hostile `not_after` must not rescue a bad signature | `signature_invalid` |
| 12 | **JWS compact** — signature over the EXACT received bytes | `pass` |
| 13 | **JWS compact** — wire-mutated payload (parsed-equal) is REJECTED | `signature_invalid` |

**Cause from the PAIR, not a boolean.** One word for two causes reads a legitimately
*rotated* peer as an attacker. Ordering is load-bearing: the JWS is verified over the
**received bytes** first, and `kid` (like every policy field) is read **only afterwards** —
so a card can never steer our verdict with attacker-chosen policy inputs.
Sig fails + `kid == fp` → `signature_invalid` (tamper/forgery); sig fails + `kid != fp` →
`anchor_stale` (this verifier cannot distinguish rotation from a forged kid *locally*).

Vocabulary now matches the adopted **door-rule** spec, so one vocabulary serves both
surfaces. This verifier evaluates **no** expiry policy — that is the door's; arm 11 asserts
the *ordering* property the door needs (a policy field can never rescue a bad signature).

**Two independent runs on two boxes, 2026-10-14 — both 13/13 `OK`, exit 0, receipt seedless,
framing rule 13/13:**

| interpreter | `cryptography` | backend used |
|---|---|---|
| a `python3` **with** `cryptography` installed | 50.0.0 | `cryptography` |
| `/usr/bin/python3` | **absent** | `pure-python-rfc8032` |

⇒ the outside verifier runs on a box with **no crypto library**, and the linked halves hold:
`signer pub == pinned anchor` on the mint side, `kid = 999df246aec5397d` (`sha256(anchor)[:16]`).

## 4. Boundaries (honest)

- **Receipts pin BYTES, not a transform.** `fixtures/` are bound to `(agent, key revision)`;
  a **rotation invalidates them** → re-run `mint_fixtures.py` on the signer's box.
- **Not a general JCS implementation.** Card surface only: keys ASCII, no floats, ints `< 2^53`.
- **The anchor is assumed known out of band.** Deciding *who the anchor is* for an outside
  partner is a separate programme decision, out of scope for this corpus.
- **Author's box ≠ witness.** A second, non-author volume must reproduce this receipt before
  it is verification rather than a self-report (`hup-verify-peer.py`: "self-witness is not witness").
