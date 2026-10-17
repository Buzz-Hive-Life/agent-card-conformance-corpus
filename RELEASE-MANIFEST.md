# Release manifest — agent-card-conformance-corpus v0.2.0

| Field | Value |
|---|---|
| Release | `agent-card-conformance-corpus` |
| Version | **v0.2.0** |
| Subject | agent **card / identity-assertion** verification — the reproducibility demonstration |
| **Corpus digest (22 files)** | **`6b6728eb265cec81dbc0e9ad0a99991847c7c3b30a29acbf4aa7fbbd3aded136`** |
| **Release digest (38 files)** | **`2f63bbd7350efd66bb785372345f06db197c33cc2c2a8e3b0b30ead6e8d2a57e`** |
| Canonical definition | `card-verify/VERIFICATION-TARGET.md` |
| Publisher | Hive Life Haven Inc. — Canada NFP (NFP Act), corp. no. 1661181-8 |
| Licence | split — Apache-2.0 (source) · CC-BY-4.0 (prose) · CC0-1.0 (fixtures) |

**An authority-adherence corpus — whether a deployed agent stays inside its declared authority under
adversarial pressure — is the next, net-new build. It does not ship here.** Every arm below tests card
format, canonicalization and signature verification.

## Two digests, deliberately

- **Corpus digest** binds the **22 executable/verdict files** — the ones that produce a verdict. It is
  the referent the conformance claim is measured against.
- **Release digest** binds the **whole release** — all 38 shipped files, including the 22 corpus
  members: licences, front-matter, the landing page, the oracle vectors, the corpus builder. Without
  it, a post-publication edit to a licence or to the front-matter would be undetectable, because the
  corpus digest keys only on the 22 verdict-producing files.

Both exclude the two documents that declare them (`RELEASE-MANIFEST.md`, `VERIFICATION-TARGET.md`) —
a file cannot contain its own hash. Every other shipped file is covered.

## Contents

| Path | What it is |
|---|---|
| `card-verify/CORPUS-v0.md` | The corpus: named arms, criteria, expected verdicts, signed front-matter |
| `card-verify/VERIFICATION-TARGET.md` | The frozen set: 22 per-file hashes + corpus digest |
| `card-verify/verify_fixture.py` | Conformance runner |
| `card-verify/oracle/verify_oracle.py` | External-reference oracle (RFC 8032 §7.1 + RFC 8785) |
| `card-verify/oracle/SOURCES.md` | Fetch URL + sha256 for every external vector file |
| `card-verify/mint_fixtures.py` | Reproduces the fixtures from published labels |
| `card-verify/fixtures/` | Committed inputs and signed blobs |
| `card-jcs-battery/card_jcs_battery.py` | The JCS canonicalizer the arms exercise |
| `scripts/hive_ed25519.py` | Vendored pure-Python Ed25519 |
| `index.html` | Landing page |

## Recompute the corpus digest

Materialize **exactly the 22 files** named in `card-verify/VERIFICATION-TARGET.md` by **basename**
into one directory `$SUBJECT`, then run — this command is the definition:

```sh
find "$SUBJECT" -name '*.pyc' -prune -o -type f ! -name VERIFICATION-TARGET.md -print0 |
  xargs -0 sha256sum | sed 's#  .*/#  #' | sort | sha256sum | cut -d' ' -f1
# expected: 2f63bbd7350efd66bb785372345f06db197c33cc2c2a8e3b0b30ead6e8d2a57e
```

Three properties this pins, each caught by running it rather than reading it: **subject = basenames**
(hashing paths would make the digest layout-dependent) · **sort key = the whole line**, not the
basename · **an exact subject, never a tree** (a directory holding extra files silently digests the
wrong thing).

## Recompute the release digest

```sh
# over every shipped file EXCEPT the two documents that declare the digests:
find . -name '*.pyc' -prune -o -type f ! -name RELEASE-MANIFEST.md ! -name VERIFICATION-TARGET.md -print0 |
  xargs -0 sha256sum | sed 's#  .*/#  #' | sort | sha256sum | cut -d' ' -f1
# expected: 90301544af82008c85ce39431f5f87acda6f634c21261f8f8c40860d149e1032
```

(Those two are excluded because a file cannot contain its own hash. Every other shipped file is
covered by this digest.)

## Recompute the verdicts

Run from the release root:

```sh
python3 card-verify/verify_fixture.py            # 13/13 arms as expected
python3 card-verify/oracle/verify_oracle.py      # arms: 29/29, exit 0
```

Both resolve their two consumed primitives **relative to the release tree** — no environment variable,
no absolute path, no crypto library required.

## Status

Published at the digests above. **This release certifies nothing and no party's conformance.** It
publishes criteria and expected verdicts. See `card-verify/CORPUS-v0.md` §1.
