#!/usr/bin/env python3
"""hive_ed25519.py — minimal Ed25519 (RFC 8032) for the Hive HA2A bridge.

Why this file exists
--------------------
The per-agent consent gate needs ASYMMETRIC signatures so a consent record
BINDS to its signer: a shared mesh secret proves only that *someone holding
the key* wrote it, not *who*. Ed25519 is the smallest, safest primitive for
that (32-byte keys, 64-byte signatures, deterministic, no parameter choices).

Two backends, one API
---------------------
* Preferred: the `cryptography` library (constant-time, audited).
* Fallback : a self-contained pure-Python RFC 8032 implementation, so the
  bridge still does real asymmetric verification on a box that lacks the
  library. The pure-Python path is SLOW and NOT constant-time — it exists so
  the gate fails *correctly* rather than failing *open*.

Both backends follow RFC 8032 and are byte-for-byte interoperable, so a key
minted by one verifies under the other.

API
---
    generate_keypair() -> (priv32, pub32)
    public_from_seed(seed32) -> pub32
    sign(priv32, msg_bytes) -> sig64
    verify(pub32, sig64, msg_bytes) -> bool

`priv32` is the 32-byte RFC 8032 *seed* (the value pasted into Railway as
HA2A_KEY_<AGENT>). It is never written to disk by the keygen tool.
"""

import hashlib
import os

# ── preferred backend ────────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey as _CPriv,
        Ed25519PublicKey as _CPub,
    )
    from cryptography.hazmat.primitives import serialization as _ser

    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover - environment dependent
    _HAVE_CRYPTO = False

BACKEND = "cryptography" if _HAVE_CRYPTO else "pure-python-rfc8032"

# ── pure-python RFC 8032 fallback ────────────────────────────────────────
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493


def _sha512(msg: bytes) -> bytes:
    return hashlib.sha512(msg).digest()


def _expmod(b: int, e: int, m: int) -> int:
    r = 1
    b %= m
    while e > 0:
        if e & 1:
            r = (r * b) % m
        e >>= 1
        b = (b * b) % m
    return r


def _inv(x: int) -> int:
    return _expmod(x, _P - 2, _P)


_d = (-121665 * _inv(121666)) % _P
_I = _expmod(2, (_P - 1) // 4, _P)


def _recover_x(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = _expmod(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


_By = (4 * _inv(5)) % _P
_Bx = _recover_x(_By)
_B = (_Bx, _By)


def _ed_add(P, Q):
    x1, y1 = P
    x2, y2 = Q
    t = _d * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + t)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - t)
    return (x3 % _P, y3 % _P)


def _scalarmult(P, e: int):
    R = (0, 1)
    while e > 0:
        if e & 1:
            R = _ed_add(R, P)
        P = _ed_add(P, P)
        e >>= 1
    return R


def _encode_point(P) -> bytes:
    x, y = P
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    return bytes(
        sum(bits[i * 8 + j] << j for j in range(8)) for i in range(32)
    )


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _decode_int(s: bytes) -> int:
    return sum(2 ** i * _bit(s, i) for i in range(256))


def _decode_point(s: bytes):
    y = sum(2 ** i * _bit(s, i) for i in range(255))
    x = _recover_x(y)
    if x & 1 != _bit(s, 255):
        x = _P - x
    return (x, y)


def _is_on_curve(P) -> bool:
    x, y = P
    return (-x * x + y * y - 1 - _d * x * x * y * y) % _P == 0


def _hint(m: bytes) -> int:
    h = _sha512(m)
    return sum(2 ** i * _bit(h, i) for i in range(512))


def _secret_scalar(seed: bytes):
    h = _sha512(seed)
    a = 2 ** 254 + sum(2 ** i * _bit(h, i) for i in range(3, 254))
    return a, h


def _py_public(seed: bytes) -> bytes:
    a, _h = _secret_scalar(seed)
    return _encode_point(_scalarmult(_B, a))


def _py_sign(seed: bytes, msg: bytes) -> bytes:
    a, h = _secret_scalar(seed)
    pk = _encode_point(_scalarmult(_B, a))
    r = _hint(h[32:64] + msg)
    Rs = _encode_point(_scalarmult(_B, r))
    S = (r + _hint(Rs + pk + msg) * a) % _L
    return Rs + S.to_bytes(32, "little")


def _py_verify(pub: bytes, sig: bytes, msg: bytes) -> bool:
    if len(sig) != 64 or len(pub) != 32:
        return False
    try:
        R = _decode_point(sig[0:32])
        A = _decode_point(pub)
    except Exception:
        return False
    S = _decode_int(sig[32:64])
    if not _is_on_curve(A) or not _is_on_curve(R) or S >= _L:
        return False
    h = _hint(sig[0:32] + pub + msg)
    return _scalarmult(_B, S) == _ed_add(R, _scalarmult(A, h))


# ── public API (backend-dispatched) ──────────────────────────────────────
def public_from_seed(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    if _HAVE_CRYPTO:
        return _CPriv.from_private_bytes(seed).public_key().public_bytes(
            _ser.Encoding.Raw, _ser.PublicFormat.Raw
        )
    return _py_public(seed)


def generate_keypair(seed: bytes = None):
    """Return (priv_seed_32, pub_32)."""
    if seed is None:
        seed = os.urandom(32)
    return seed, public_from_seed(seed)


def sign(priv_seed: bytes, msg: bytes) -> bytes:
    if len(priv_seed) != 32:
        raise ValueError("Ed25519 private seed must be 32 bytes")
    if _HAVE_CRYPTO:
        return _CPriv.from_private_bytes(priv_seed).sign(msg)
    return _py_sign(priv_seed, msg)


def verify(pub: bytes, sig: bytes, msg: bytes) -> bool:
    """True iff `sig` is a valid Ed25519 signature by `pub` over `msg`.
    Never raises — a malformed key/signature returns False (fail closed)."""
    if not pub or not sig:
        return False
    if _HAVE_CRYPTO:
        try:
            _CPub.from_public_bytes(pub).verify(sig, msg)
            return True
        except Exception:
            return False
    try:
        return _py_verify(pub, sig, msg)
    except Exception:
        return False
