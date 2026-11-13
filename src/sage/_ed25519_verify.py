"""Pure-Python Ed25519 signature verification (RFC 8032, section 5.1.7). Verification only.

Used by the single-file verifier when the ``cryptography`` package is unavailable. It handles only
public inputs (public key, message, signature), so it has no secret-dependent timing to protect.
It rejects non-canonical ``S`` (``S >= L``) and keys or ``R`` values that do not decode to a curve
point, and checks the cofactorless equation ``[S]B == R + [k]A`` like OpenSSL.
"""

from __future__ import annotations

import hashlib

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
_IDENTITY = (0, 1, 1, 0)


def _add(p1: tuple[int, int, int, int], p2: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    a = (p1[1] - p1[0]) * (p2[1] - p2[0]) % _P
    b = (p1[1] + p1[0]) * (p2[1] + p2[0]) % _P
    c = 2 * p1[3] * p2[3] * _D % _P
    d = 2 * p1[2] * p2[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(scalar: int, point: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    result = _IDENTITY
    while scalar:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _equal(p1: tuple[int, int, int, int], p2: tuple[int, int, int, int]) -> bool:
    return (p1[0] * p2[2] - p2[0] * p1[2]) % _P == 0 and (p1[1] * p2[2] - p2[1] * p1[2]) % _P == 0


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _decompress(data: bytes) -> tuple[int, int, int, int] | None:
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _recover_x(_GY, 0)
assert _GX is not None
_BASE = (_GX, _GY, 1, _GX * _GY % _P)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return True only if ``signature`` is a valid Ed25519 signature of ``message`` by ``public_key``."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a = _decompress(public_key)
    r = _decompress(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % _L
    return _equal(_mul(s, _BASE), _add(r, _mul(k, a)))


class PurePublicKey:
    """Duck-types the ``verify(signature, data)`` method of cryptography's ``Ed25519PublicKey``."""

    def __init__(self, raw: bytes) -> None:
        if len(raw) != 32 or _decompress(raw) is None:
            raise ValueError("invalid Ed25519 public key")
        self._raw = raw

    def verify(self, signature: bytes, data: bytes) -> None:
        if not verify(self._raw, data, signature):
            raise ValueError("signature does not match the pinned public key")
