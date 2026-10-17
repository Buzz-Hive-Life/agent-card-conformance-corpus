# Oracle sources (external references)

Every file below was **fetched in this session** (not recalled) and its sha256 recorded at fetch time.

| File | Source URL | HTTP | Fetched | sha256 |
|---|---|---|---|---|
| `rfc8032_ed25519.json` | `https://www.rfc-editor.org/rfc/rfc8032.txt` §7.1 (RFC 8032, Jan 2017) | 200 | 2026-10-15 | `ed63657ff389301282b169b0abde9b5dd2c7e4d524fdfa5da6ff3094fc93c4c3` *(whole RFC text)* |
| `rfc8785_jcs/input_arrays.json` | `https://raw.githubusercontent.com/cyberphone/json-canonicalization/master/testdata/input/arrays.json` | 200 | 2026-10-15 | `e503b6d71d1afa595b1c74b1016445c944cd89f90418066b23de1aeda7d17563` |
| `rfc8785_jcs/output_arrays.json` | `.../testdata/output/arrays.json` (the reference canonicalizer's output) | 200 | 2026-10-15 | `099601b171cafed97c333f8878d68e7f8c8f795412adb34b2fdcf0e7c7beac42` |
| `rfc8785_jcs/input_french.json` | `.../testdata/input/french.json` | 200 | 2026-10-15 | `03676a951cd8753ac62589f72eb2105cc782c33425418cfe1d517c111f6e5d5a` |
| `rfc8785_jcs/output_french.json` | `.../testdata/output/french.json` | 200 | 2026-10-15 | `d99d0ebdcb0033cb858cfa830ae46bc0fb3309413b271f1da828c89901a27ed5` |

**Why external matters:** the corpus's own fixtures were authored by us. Reproducing *our* expected verdicts proves the instrument is deterministic — it does not prove it is **correct**. These vectors are authored by parties with no relationship to the Hive, which is what makes the verdict leg checkable against something other than itself.
