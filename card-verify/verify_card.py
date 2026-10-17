#!/usr/bin/env python3
"""verify_card.py — OUT-OF-HIVE verifier for a signed Hive agent card.

Purpose: an outside verifier with no shared state checks the card —
  "an outside verifier holding no shared table verifies our card."

Design rules that make that true:
  * This module reads the trust store NOTHING and the signer's PRIVATE key never
    (the signer side is a different role — see `mint_fixtures.py`). No
    no Hive key material and no seed material at verify time.
  * It consumes the FLEET's two published primitives instead of re-implementing
    them: the canonicalizer (`../card-jcs-battery/card_jcs_battery.py`) and
    Ed25519 (`scripts/hive_ed25519.py`) — ONE implementation of each, not two.
    `hive_ed25519` falls back to pure-python RFC 8032, so this verifier runs on
    a box with NO `cryptography` installed.
  * The trust anchor is a PARAMETER (an out-of-band pinned public key, hex),
    never a fetch. Discovery (a JWKS the card points at) may CONFIRM the anchor
    and can NEVER supply the key. That is the outside-verifier counterpart of
    the Hive module's invariant: TRUST STORE IS PINNED.

Verdict vocabulary (a mismatch is NAMEABLE FROM THE PAIR, never a bare "invalid" —
one boolean for two causes is how a legitimately rotated peer gets read as an attacker):
  pass | format_drift | key_mismatch | signature_invalid | anchor_stale
  | jwks_anchor_mismatch | refused_nonascii_key | refused_float
  | refused_int_range | no_pinned_anchor | malformed

Order matters: the JWS is verified over the RECEIVED BYTES first; `kid` (and any
other policy field) is read only afterwards, so it can never steer the verdict.
"""
import base64
import hashlib
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))


def _locate(filename: str, *cands: str) -> str | None:
    for c in cands:
        if c and os.path.isfile(os.path.join(c, filename)):
            return os.path.abspath(c)
    return None


# --- consume the fleet's canonicalizer (an algorithm, not a table) ---
# An outsider fetches these two published artifacts too; accept either the repo
# layout or a flat copy, and allow an explicit override.
_jcs = _locate("card_jcs_battery.py", os.environ.get("CARD_JCS_DIR"),
               os.path.join(_HERE, "..", "card-jcs-battery"),
               os.path.join(_HERE, "card-jcs-battery"), _HERE)
if not _jcs:
    raise SystemExit("card_jcs_battery.py not found (set CARD_JCS_DIR)")
sys.path.insert(0, _jcs)
from card_jcs_battery import jcs_bytes, house_bytes  # noqa: E402

# --- consume the fleet's Ed25519 (one implementation, stdlib fallback) ---
_ed = _locate("hive_ed25519.py", os.environ.get("HIVE_ED25519_DIR"),
              os.path.join(_HERE, os.pardir, "scripts"),          # release layout
              os.path.join(_HERE, os.pardir, os.pardir, "scripts"),
              os.path.join(_HERE, os.pardir, os.pardir, os.pardir, "scripts"),  # repo layout
              os.path.join(_HERE, "..", "scripts"),
              os.path.join(_HERE, "..", "hive_ed25519"), _HERE)
if not _ed:
    raise SystemExit("hive_ed25519.py not found (set HIVE_ED25519_DIR)")
sys.path.insert(0, _ed)
import hive_ed25519 as _H  # noqa: E402


def backend() -> str:
    """Which Ed25519 backend the fleet primitive resolved to on this box."""
    return _H.BACKEND


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


_TWO53 = 2 ** 53


def _bad_number(o) -> str | None:
    """The card surface admits no float and no integer outside the JCS-exact
    range. `float` -> non-JCS bytes (1.0 vs 1); an int with |n| >= 2^53 is not
    exactly representable as an IEEE-754 double, so its JCS form diverges too
    (measured: 9007199254740993 -> ...992). Refuse BOTH loudly -- never verify
    over bytes an outsider's canonicalizer would not reproduce."""
    if isinstance(o, bool):          # bool is an int subclass; it is not a number here
        return None
    if isinstance(o, float):
        return "float"
    if isinstance(o, int) and abs(o) >= _TWO53:
        return "int"
    if isinstance(o, dict):
        return next((r for v in o.values() if (r := _bad_number(v))), None)
    if isinstance(o, list):
        return next((r for v in o if (r := _bad_number(v))), None)
    return None


def _nonascii_key(o, path="") -> str | None:
    """RFC 8785 sorts object keys by UTF-16 code unit; Python sorts by code
    point. They agree only on ASCII keys -> assert card KEYS are ASCII. This
    belongs in the CARD contract, never inside jcs_bytes() (RFC 8785's own
    golden vectors carry non-ASCII keys and MUST still canonicalize)."""
    if isinstance(o, dict):
        for k, v in o.items():
            if not isinstance(k, str):
                return f"{path}/<nonstr-key>"
            if not k.isascii():
                return f"{path}/{k!r}"
            hit = _nonascii_key(v, f"{path}/{k}")
            if hit:
                return hit
    elif isinstance(o, list):
        for i, v in enumerate(o):
            hit = _nonascii_key(v, f"{path}[{i}]")
            if hit:
                return hit
    return None


def _classify(card: dict, jwks: dict | None, anchor_pub_hex: str) -> dict:
    """DETACHED form. card: {"payload": {...}, "signature": "<hex64>"}.

    DECLARED ≠ ACTUAL, stated plainly: this form verifies the signature over the
    CANONICALIZATION of the parsed payload — the wire bytes as received are gone
    by the time this is called. So for THIS form interop rests on CANONICALIZER
    EQUALITY, and a wire-mutated card whose parsed content is unchanged is
    ACCEPTED. Use `verify_bytes()` (JWS compact) for true received-bytes semantics.
    """
    if not isinstance(card, dict) or "payload" not in card or "signature" not in card:
        return {"verdict": "malformed", "why": "card needs payload+signature"}

    payload = card["payload"]
    if not isinstance(payload, dict):
        return {"verdict": "malformed", "why": "payload must be an object"}

    # --- surface guards: fail LOUD, never verify over non-JCS bytes ---
    nk = _nonascii_key(payload)
    if nk:
        return {"verdict": "refused_nonascii_key", "why": f"non-ASCII key at {nk}"}
    bn = _bad_number(payload)
    if bn == "float":
        return {"verdict": "refused_float", "why": "card surface excludes floats"}
    if bn == "int":
        return {"verdict": "refused_int_range",
                "why": "integer |n| >= 2^53 is not JCS-exact (IEEE-754)"}

    raw_anchor = (anchor_pub_hex or "").strip()
    if not raw_anchor:
        return {"verdict": "no_pinned_anchor",
                "why": "no anchor supplied — cannot verify, and discovery must "
                       "never be allowed to supply one"}
    try:
        anchor = bytes.fromhex(raw_anchor)
    except ValueError:
        return {"verdict": "malformed", "why": "anchor not hex"}
    if len(anchor) != 32:
        return {"verdict": "malformed", "why": f"anchor {len(anchor)}B, need 32"}

    fp = hashlib.sha256(anchor).hexdigest()[:16]

    if payload.get("alg") not in (None, "EdDSA", "Ed25519"):
        return {"verdict": "malformed", "why": f"unexpected alg {payload.get('alg')}"}

    try:
        sig = bytes.fromhex(str(card["signature"]).strip())
    except ValueError:
        return {"verdict": "malformed", "why": "signature not hex"}
    if len(sig) != 64:
        return {"verdict": "malformed", "why": f"signature {len(sig)}B, need 64"}

    # ── 1. CRYPTO FIRST, over the RECEIVED BYTES ─────────────────────────────
    # kid / not_after / any policy field is read only AFTER the signature is
    # settled — otherwise a card could steer our verdict with attacker-chosen
    # policy inputs before we ever check who signed it.
    sig_over_jcs = _H.verify(anchor, sig, jcs_bytes(payload))

    # ── 2. policy fields, now safe to read ───────────────────────────────────
    kid = str(payload.get("kid", ""))

    if sig_over_jcs:
        if kid != fp:
            # signed by the pinned key, but the card declares another name
            return {"verdict": "key_mismatch",
                    "why": f"valid signature under the anchor, but card kid="
                           f"{kid or '<none>'} != anchor fingerprint={fp}"}
        if jwks:
            try:
                x = jwks["keys"][0]["x"]
                advertised = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
            except Exception:
                advertised = b""
            if advertised != anchor:
                return {"verdict": "jwks_anchor_mismatch",
                        "why": "served JWKS does NOT match the pinned anchor "
                               "(discovery repointed); anchor wins, refuse"}
        return {"verdict": "pass", "kid": fp}

    # ── 3. signature failed: name the CAUSE from the pair ────────────────────
    if _H.verify(anchor, sig, house_bytes(payload)):
        return {"verdict": "format_drift",
                "why": "signature verifies over HOUSE bytes, not JCS -> "
                       "two canonicalizers (non-compliant to an outsider)"}
    if kid == fp:
        return {"verdict": "signature_invalid",
                "why": "kid matches the pinned anchor but the signature does not "
                       "verify -> tamper/forgery"}
    return {"verdict": "anchor_stale",
            "why": "kid != pinned anchor AND signature does not verify: this "
                   "verifier cannot distinguish a ROTATED anchor from a forged "
                   "kid locally — re-pin out of band"}


# ── verdict framing: NO verdict may select a remedy ──────────────────────────
# Every refusal here is derived from UNAUTHENTICATED input (it is computed before
# or independently of a valid signature), so an attacker can influence *which*
# refusal is named. Therefore none is actionable: only `pass` grants trust, and
# `anchor_stale` is ADVISORY-ONLY — surfaced to a human, never an automatic
# re-pin. A re-pin is a trust-store WRITE; letting a received card's verdict
# trigger one would hand an unauthenticated field a lever into the trust store.
def _finish(d: dict) -> dict:
    d.setdefault("actionable", False)
    if d.get("verdict") == "anchor_stale":
        d["advisory_only"] = True
        d["remedy"] = "surface to a human; never auto re-pin from a received card"
    return d


def verify(card: dict, jwks: dict | None, anchor_pub_hex: str) -> dict:
    """DETACHED form, already parsed. Canonicalizer-equality caveat: see `_classify`."""
    return _finish(_classify(card, jwks, anchor_pub_hex))


_JWS_COMPACT = re.compile(rb"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


def _b64u_dec(seg: bytes) -> bytes:
    return base64.urlsafe_b64decode(seg + b"=" * (-len(seg) % 4))


def _classify_jws(compact: bytes, anchor_pub_hex: str, jwks: dict | None) -> dict:
    """JWS compact (RFC 7515 §7.1): `header.payload.signature`, all base64url.
    The signing input is the EXACT received bytes `header.payload` — NO
    canonicalization is in the path, so a wire-mutated card is REJECTED and
    interop is whole-class rather than canonicalizer-dependent. `kid` is read
    from the PROTECTED header, which the signature authenticates (not the payload).
    """
    h, p, s = compact.split(b".")
    raw_anchor = (anchor_pub_hex or "").strip()
    if not raw_anchor:
        return {"verdict": "no_pinned_anchor",
                "why": "no anchor supplied — cannot verify; discovery never supplies one"}
    try:
        anchor = bytes.fromhex(raw_anchor)
    except ValueError:
        return {"verdict": "malformed", "why": "anchor not hex"}
    if len(anchor) != 32:
        return {"verdict": "malformed", "why": f"anchor {len(anchor)}B, need 32"}
    fp = hashlib.sha256(anchor).hexdigest()[:16]
    try:
        header = json.loads(_b64u_dec(h).decode("utf-8"))
    except Exception:
        return {"verdict": "malformed", "why": "protected header not JSON"}
    if header.get("alg") not in ("EdDSA", "Ed25519"):
        return {"verdict": "malformed", "why": f"unexpected alg {header.get('alg')}"}
    try:
        sig = _b64u_dec(s)
    except Exception:
        return {"verdict": "malformed", "why": "signature not base64url"}
    if len(sig) != 64:
        return {"verdict": "malformed", "why": f"signature {len(sig)}B, need 64"}

    # crypto over the EXACT received bytes — the entire point of this form
    if _H.verify(anchor, sig, h + b"." + p):
        kid = str(header.get("kid", ""))
        if kid != fp:
            return {"verdict": "key_mismatch",
                    "why": f"valid signature, but protected kid={kid or '<none>'} "
                           f"!= anchor fingerprint={fp}"}
        if jwks:
            try:
                x = jwks["keys"][0]["x"]
                advertised = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
            except Exception:
                advertised = b""
            if advertised != anchor:
                return {"verdict": "jwks_anchor_mismatch",
                        "why": "served JWKS does NOT match the pinned anchor"}
        # surface contract, now on an AUTHENTICATED payload
        try:
            payload = json.loads(_b64u_dec(p).decode("utf-8"))
        except Exception:
            return {"verdict": "malformed", "why": "payload not JSON"}
        nk = _nonascii_key(payload)
        if nk:
            return {"verdict": "refused_nonascii_key", "why": f"non-ASCII key at {nk}"}
        bn = _bad_number(payload)
        if bn == "float":
            return {"verdict": "refused_float", "why": "card surface excludes floats"}
        if bn == "int":
            return {"verdict": "refused_int_range",
                    "why": "integer |n| >= 2^53 is not JCS-exact"}
        return {"verdict": "pass", "kid": fp, "form": "jws-compact"}

    kid = str(header.get("kid", ""))
    if kid == fp:
        return {"verdict": "signature_invalid",
                "why": "protected kid matches the anchor but the signature does "
                       "not verify -> tamper/forgery"}
    return {"verdict": "anchor_stale",
            "why": "protected kid != anchor AND signature does not verify: cannot "
                   "distinguish a rotated anchor from a forged kid locally"}


def verify_bytes(raw: bytes, anchor_pub_hex: str, jwks: dict | None = None) -> dict:
    """The RECEIVED-BYTES entry point. If `raw` is JWS compact, the signature is
    checked over the exact bytes received (no canonicalizer in the path). Else it
    falls back to the detached JSON form, which requires canonicalizer equality."""
    if raw is None:
        return _finish({"verdict": "malformed", "why": "no card bytes"})
    b = raw.strip() if isinstance(raw, (bytes, bytearray)) else str(raw).encode()
    if _JWS_COMPACT.match(b):
        return _finish(_classify_jws(b, anchor_pub_hex, jwks))
    try:
        card = json.loads(b.decode("utf-8"))
    except Exception:
        return _finish({"verdict": "malformed",
                        "why": "not JWS compact, and not valid JSON"})
    return _finish(_classify(card, jwks, anchor_pub_hex))
