# VERIFICATION TARGET — card-verify (FROZEN)

**Pinned by:** the corpus maintainer · 2026-10-14
**Frozen at:** origin/main `8b649a3`
**Rev:** 1 → **2** → **3** → **4** → **5** (2026-10-15)

> **REV 2 — the referent was repaired.** Rev 1's recompute command (`sed 's#.*/##'`) was
> **greedy**: `.*` ate the hash *and* the path, so the preimage was the bare **basename
> list** and `TARGET_DIGEST 1c5f95a5…` pinned **filenames, not bytes** — emptying a member
> left it unchanged. Caught in review — independently reproduced here:
> `hive_ed25519.py` emptied to 0 B → digest unchanged; `card_pass.json` +1 byte → unchanged.
> Rev 2's command keeps the hash, so the pin is content-bound again:
> **`TARGET_DIGEST` = `8fcb2328…`**. Rev 1's value is *superseded*, never wrong for its own
> recipe. Per this file's own rule: a new revision with a new declared hash.

> **REV 3 — re-pinned after the v0.2.0 re-mint.** The fixtures were re-minted on neutral,
> reserved identities (`test-agent` / `example.com`) with signing material derived from a
> **published label**, and `mint_fixtures.py` no longer references any Hive path. Fixture bytes
> therefore changed, and per this file's own rule that is *a new revision with a new declared
> hash* — not an in-place edit. Current content-bound value:
> **`TARGET_DIGEST` = `be09f41a57afa9b161e243966a2b2f57df3603eb9d613d8435e3bbca69c1350e`**. Rev 2's `8fcb2328…` and rev 1's `1c5f95a5…` are *superseded*,
> never wrong for their own recipe.
> **Caught by the pre-publication review:** the manifest had not followed the re-mint,
> so 16 of its 22 per-file rows no longer matched the bytes on `main` — a declared digest read
> as evidence, the exact failure this pin exists to prevent.

> **REV 5 — wording pass.** Internal protocol jargon removed from three pinned files. Bytes changed,
> so the pin moves: **`TARGET_DIGEST` = `6b6728eb265cec81dbc0e9ad0a99991847c7c3b30a29acbf4aa7fbbd3aded136`**.
>
> **REV 4 — pre-publication repair.** Three defects found by the pre-publication review: an absolute
> internal path in the consumed canonicalizer (inside this pinned set), the Ed25519 resolution
> failing in a standalone release layout, and one declared path that did not resolve in the
> published tree. All three are fixed, so per this file's own rule the pin moves:
> **`TARGET_DIGEST` = `577baac85883f0c979f449970ed57e35a38b1767712e79dd4789252aa07a303b`**. Rev 3's `be09f41a…` is *superseded* — correct for its own byte-set.
A verification target that keeps moving can never be *closed*, only *re-verified forever*
(three receipts against three different byte-sets in one session). So the set below is
**frozen**: it is the referent criterion #1 is measured against.

## The rule

> **A receipt pins BYTES, not a transform.** Any change to a file in the set is a **new
> revision with a new declared hash** — never an in-place edit. A receipt that names an older
> hash is honest and *superseded*, not wrong.

**TARGET_DIGEST** — the sha256 of the sorted `sha256sum` lines, each reduced to
`<full-hash>  <basename>`, sorted **lexicographically by the whole line**:

```
6b6728eb265cec81dbc0e9ad0a99991847c7c3b30a29acbf4aa7fbbd3aded136
```

*(rev 2, superseded: `8fcb232829c2f37d9d834a7aae6c904446bad35400cbf6514d8fe9b34fd6aed8` — correct
for the pre-re-mint byte-set. Rev 1, superseded: `1c5f95a5dff1289bb81a6c2a112571e62504f78695bc8f5e66e8581479b70dc6`
— the basename-set digest. Both kept so old receipts resolve to their own recipe.)*

**Subject = basenames, deliberately.** The first version of this manifest hashed *paths*
(`card-verify/verify_card.py`, …), which made the digest **layout-dependent** — the same bytes
copied flat produced a different digest. Caught by *running* it from a flat copy, which is the
exact **declared ≠ actual** class this thread is built against. Over basenames the digest is
invariant: recomputed **identical** from the origin layout and from a flat copy
(`8fcb2328…` both, on rev 2). (A second correction, same session: the sort key had to be pinned too — sorting by
basename gives a different value than sorting by the full line, so the command below **is** the
definition.)

Excluded from the set: this manifest, any checker, and `__pycache__`/`*.pyc` build artifacts.

**Canonical definition / recompute** — this exact command *is* the spec. Note it takes an
**exact subject**, never a directory (rule 8): pointing at a *tree* that contains
more than the set silently digests the wrong thing — measured here, the whole `docs/peer-lane/`
tree gives `88a3a52a…`, a plausible number for a subject nobody declared.

```sh
# 1. materialize EXACTLY the 22 files in the table below (from origin, by name), then:
find <exact-subject-dir> -name '*.pyc' -prune -o -type f ! -name VERIFICATION-TARGET.md -print0 \
  | xargs -0 sha256sum | sed 's#  .*/#  #' | sort | sha256sum | cut -d' ' -f1
```

**Locale is not a hazard — under rev 2 only, and now measured on two boxes.** With the hash
preserved every line is hash-prefixed, so the primary sort key is hex and collation has nothing
to reorder: 🐳 (`C` / `POSIX` / `C.utf8` — this box carries no glibc locale that reorders those
names) and a second box (`en_US.UTF-8`) both give `8fcb2328…`. Under **rev 1** the preimage was
bare basenames, so collation *was* in the preimage — and rev 1 nonetheless recorded "no hazard",
measured on boxes carrying only `C` locales, where it could not have failed. The conclusion
survives; the *reason* is restated here because rev-1's wording ("each line is hash-prefixed")
was made untrue by rev 1's own command. Recorded as a negative so nobody "fixes" it later.

## The frozen set (22 files)

| sha256 (16) | file |
|---|---|
| `78e97634e2efdc85` | `card-jcs-battery/card_jcs_battery.py` |
| `d6391aca950fb02c` | `card-verify/README.md` |
| `b46d9288ff870dd8` | `card-verify/fixtures/anchor.hex` |
| `e3b0c44298fc1c14` | `card-verify/fixtures/anchor_empty.hex` |
| `816b2627935b5d2f` | `card-verify/fixtures/anchor_foreign.hex` |
| `0d5c7fff64b76aac` | `card-verify/fixtures/card_big_int.json` |
| `5ca719aaab2b9ebb` | `card-verify/fixtures/card_drift.json` |
| `d2201d74378334e3` | `card-verify/fixtures/card_float.json` |
| `5c3dd2be213e48cb` | `card-verify/fixtures/card_jws_compact.txt` |
| `720a0d3e686ae326` | `card-verify/fixtures/card_jws_wire_mutated.txt` |
| `01d58a2dc495e91e` | `card-verify/fixtures/card_kid_mismatch.json` |
| `3e1fe5fca23346d2` | `card-verify/fixtures/card_nonascii_key.json` |
| `302f63ad78ec954f` | `card-verify/fixtures/card_pass.json` |
| `2276a2d1ad0227b8` | `card-verify/fixtures/card_tampered.json` |
| `5f9b5aaf8a546a25` | `card-verify/fixtures/card_tampered_expiry.json` |
| `a9170e6c3f491b65` | `card-verify/fixtures/cases.json` |
| `628aa54f285ef60a` | `card-verify/fixtures/jwks.json` |
| `649686d839101e04` | `card-verify/fixtures/jwks_repoint.json` |
| `a481bbca6e368512` | `card-verify/mint_fixtures.py` |
| `9a629a441ab42cdc` | `card-verify/verify_card.py` |
| `090b283cb56cd802` | `card-verify/verify_fixture.py` |
| `1a5b1d50e2633c4a` | `scripts/hive_ed25519.py` |

**Reference receipt against THIS target:** 13/13 arms, framing rule 13/13, exit 0, `kid`
`999df246aec5397d`, from a flat copy under `env -i` with an isolated HOME, bare
`python3` (no `cryptography` → `pure-python-rfc8032`), 0 trust-store/seed files in the run tree.
Non-author reproduction is still owed on this revision (see the thread) — this manifest fixes
the *referent*, it does not itself discharge criterion #1.

**The negative control must be a CONTENT tamper.** Mutate one byte of a member and confirm the
digest *moves* (`8fcb2328…` → something else). Adding a file only moves the **name list** — the
exact class rev 1 could not see, so an added-file control passes on a content-blind pin.
