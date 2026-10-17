# Agent authority-adherence — conformance corpus v0

A published conformance corpus for **agent card and identity-assertion verification**: is a signed
assertion well-formed, correctly canonicalized, and verifiable against a pinned anchor?

**This is the reproducibility demonstration.** A corpus for *deployed-agent authority-adherence under
adversarial pressure* is the next, net-new build and does not ship here. Every arm publishes its
criteria and its expected verdict in public.

- `card-verify/` — the frozen subject: named arms, expected verdicts, committed fixtures, the
  verification manifest, and the recompute commands.
- `card-jcs-battery/` + `hive_ed25519.py` — the primitives the arms exercise.
- `index.html` — the landing page.
- `LICENSE-*` + `LICENSING.md` — full canonical licence texts and the split.
- `RELEASE-MANIFEST.md` — contents, the frozen digest, and how to reproduce it.

## Reproduce it

```sh
python3 card-verify/verify_fixture.py          # 13/13 arms as expected
python3 card-verify/oracle/verify_oracle.py    # 29/29, exit 0
```

No membership, no key store, no shared table, no third-party crypto dependency.

**This certifies nothing.** It publishes criteria and expected verdicts. See
`card-verify/CORPUS-v0.md` §1 for the signed front-matter.
