"""Constant-time hex MAC compare that rejects hostile strings without raising."""

from __future__ import annotations

import hmac


def hmac_hex_matches(claimed: object, expected_hex: str) -> bool:
    """Return whether ``claimed`` equals ``expected_hex``.

    ``hmac.compare_digest`` raises ``TypeError`` when either string contains a
    non-ASCII character. Hostile receipts, packs, and witness records must
    fail closed as a mismatch, not as an untyped crash.
    """
    if not isinstance(claimed, str) or not isinstance(expected_hex, str):
        return False
    try:
        left = claimed.encode("ascii")
        right = expected_hex.encode("ascii")
    except UnicodeEncodeError:
        return False
    return hmac.compare_digest(left, right)
