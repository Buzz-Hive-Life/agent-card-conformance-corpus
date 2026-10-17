#!/usr/bin/env python3
"""mint_fixtures.py — SIGNER side. Runs ONLY on the box where the key IS.

This is the publisher's half: it reads the agent's volume seed, signs the card
payloads with the fleet's Ed25519 primitive, and writes a self-contained
`fixtures/` set + `cases.json` manifest. The verifier side (`verify_fixture.py`)
then runs with ZERO Hive state — this script is the ONLY part that touches a
private key, and it is a different role from verification.

Rerun after a KEY ROTATION: a receipt pins BYTES, not a transform — the committed
fixtures are bound to (agent, key revision) and a rotation invalidates them.

Test material is derived from PUBLISHED labels (see _test_seed) - no fleet key, no Hive path, no real agent identity.
"""
import base64, hashlib, json, os, sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "..", "card-jcs-battery"))
sys.path.insert(0, os.path.join(_HERE, "..", "..", "..", "scripts"))
from card_jcs_battery import jcs_bytes, house_bytes
import hive_ed25519 as H

# --- corpus-local, published test material (no fleet key, no Hive paths) --------
# The published corpus must not carry a real fleet key or a real agent's identity.
# Every key below is DERIVED from a published label, so any stranger can re-mint
# this fixture set byte-for-byte and confirm it signs nothing real.
AGENT = "test-agent"
OUT = os.path.join(_HERE, "fixtures")

def _test_seed(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()

seed = _test_seed("hive-card-verify-corpus/test-agent/v0.2.0")
anchor = H.public_from_seed(seed).hex()
foreign = H.public_from_seed(_test_seed("hive-card-verify-corpus/foreign/v0.2.0")).hex()
assert len(seed) == 32 and len(anchor) == 64

fp = hashlib.sha256(bytes.fromhex(anchor)).hexdigest()[:16]
b64u = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")


def payload(**o):
    p = {"agent": AGENT, "alg": "EdDSA", "display": "\U0001F9EA Example Agent",
         "iss": "example.com", "kid": fp, "role": "Example Agent Role",
         "not_after": "2027-10-14T00:00:00Z"}
    p.update(o)
    return p


def sign(p, *, over="jcs"):
    msg = jcs_bytes(p) if over == "jcs" else house_bytes(p)
    return {"payload": p, "signature": H.sign(seed, msg).hex()}


os.makedirs(OUT, exist_ok=True)
jwks = {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": fp, "x": b64u(bytes.fromhex(anchor))}]}
jwks_bad = {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": fp, "x": b64u(b"\x11" * 32)}]}

tampered = sign(payload()); tampered["payload"]["role"] = "Example Agent Rle"
# ordering arm: a hostile policy field (`not_after` far in the future) must NOT
# rescue a bad signature -> still signature_invalid, never "trusted/policy-ok".
tampered_expiry = sign(payload(not_after="9999-12-31T23:59:59Z"))
tampered_expiry["payload"]["role"] = "Example Agent Rle"
nonascii = {"payload": payload(), "signature": "00" * 64}
nonascii["payload"]["identit\u00e9"] = "x"


def jws(payload_obj, *, pretty=True):
    """JWS compact (RFC 7515 §7.1). Signing input = EXACT received bytes
    `header.payload` — no canonicalization anywhere in the path."""
    hb = json.dumps({"alg": "EdDSA", "kid": fp, "typ": "JOSE"},
                    separators=(",", ":")).encode()
    pj = (json.dumps(payload_obj, indent=2).encode() if pretty
          else json.dumps(payload_obj, separators=(",", ":")).encode())
    si = b64u(hb) + "." + b64u(pj)
    return si + "." + b64u(H.sign(seed, si.encode()))


card_compact = jws(payload())
# WIRE-MUTATED but PARSED-EQUAL: same header + same signature, payload re-encoded
# densely. Received-bytes semantics must REJECT it; the detached form of the very
# same parsed payload (card_pass.json) ACCEPTS it — that contrast is the point.
_h, _p, _s = card_compact.split(".")
wire_mutated = _h + "." + b64u(json.dumps(payload(), separators=(",", ":")).encode()) + "." + _s

files = {
    "card_pass.json": sign(payload()),
    "card_drift.json": sign(payload(), over="house"),
    "card_kid_mismatch.json": sign(payload(kid="deadbeefdeadbeef")),
    "card_tampered.json": tampered,
    "card_tampered_expiry.json": tampered_expiry,
    "card_nonascii_key.json": nonascii,
    "card_float.json": {"payload": payload(version=1.0), "signature": "00" * 64},
    "card_big_int.json": {"payload": payload(seq=9007199254740993), "signature": "00" * 64},
    "jwks.json": jwks,
    "jwks_repoint.json": jwks_bad,
    "anchor.hex": anchor + "\n",
    "anchor_foreign.hex": foreign + "\n",
    "anchor_empty.hex": "",
    "card_jws_compact.txt": card_compact + "\n",
    "card_jws_wire_mutated.txt": wire_mutated + "\n",
}
for name, obj in files.items():
    with open(os.path.join(OUT, name), "w") as f:
        json.dump(obj, f, indent=2) if isinstance(obj, dict) else f.write(obj)

cases = [
    {"name": "positive control — tamper-free JCS card", "card": "card_pass.json", "jwks": "jwks.json", "anchor": "anchor.hex", "expect": "pass"},
    {"name": "format_drift — signed over HOUSE bytes", "card": "card_drift.json", "jwks": "jwks.json", "anchor": "anchor.hex", "expect": "format_drift"},
    {"name": "key_mismatch — valid sig under the anchor, foreign kid declared", "card": "card_kid_mismatch.json", "jwks": "jwks.json", "anchor": "anchor.hex", "expect": "key_mismatch"},
    {"name": "signature_invalid — kid==fp, a field mutated after signing", "card": "card_tampered.json", "jwks": "jwks.json", "anchor": "anchor.hex", "expect": "signature_invalid"},
    {"name": "jwks repointed — discovery disagrees with anchor", "card": "card_pass.json", "jwks": "jwks_repoint.json", "anchor": "anchor.hex", "expect": "jwks_anchor_mismatch"},
    {"name": "axis-3 — non-ASCII card KEY", "card": "card_nonascii_key.json", "jwks": "jwks.json", "anchor": "anchor.hex", "expect": "refused_nonascii_key"},
    {"name": "axis-2 — float in the card", "card": "card_float.json", "jwks": "jwks.json", "anchor": "anchor.hex", "expect": "refused_float"},
    {"name": "axis-2 — int beyond JCS-exact range (|n| >= 2^53)", "card": "card_big_int.json", "jwks": "jwks.json", "anchor": "anchor.hex", "expect": "refused_int_range"},
    {"name": "anchor_stale — kid!=fp and sig fails (rotation vs forged kid: indistinguishable locally)", "card": "card_pass.json", "jwks": "jwks.json", "anchor": "anchor_foreign.hex", "expect": "anchor_stale"},
    {"name": "no_pinned_anchor — no anchor supplied (discovery must not fill in)", "card": "card_pass.json", "jwks": "jwks.json", "anchor": "anchor_empty.hex", "expect": "no_pinned_anchor"},
    {"name": "ORDERING — hostile not_after must not rescue a bad signature", "card": "card_tampered_expiry.json", "jwks": "jwks.json", "anchor": "anchor.hex", "expect": "signature_invalid"},
    {"name": "JWS compact — signature over the EXACT received bytes", "card": "card_jws_compact.txt", "form": "raw", "anchor": "anchor.hex", "expect": "pass"},
    {"name": "JWS compact — wire-mutated payload (parsed-equal) is REJECTED", "card": "card_jws_wire_mutated.txt", "form": "raw", "anchor": "anchor.hex", "expect": "signature_invalid"},
]
with open(os.path.join(OUT, "cases.json"), "w") as f:
    json.dump({"agent": AGENT, "kid": fp, "backend": H.BACKEND, "cases": cases}, f, indent=2)

print(f"minted {len(files)} fixture files + cases.json for agent={AGENT} kid={fp} (backend={H.BACKEND})")
