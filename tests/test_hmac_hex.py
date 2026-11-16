"""Hostile MAC strings must fail closed, not raise TypeError.

Scheduled Atheris job fuzz_receipt (run 43869899064 on main f032956) crashed in
hmac.compare_digest when a receipt MAC contained a non-ASCII character.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sage.errors import ChainIntegrityError, ReceiptMismatchError, SecurityDivergence
from sage.heal_capability import HealCapability
from sage.hmac_hex import hmac_hex_matches
from sage.pack import verify_pack_meta
from sage.receipt import verify_receipt, write_receipt
from sage.recorder import SageRecorder


def test_hmac_hex_matches_ascii_only():
    assert hmac_hex_matches("ab", "ab") is True
    assert hmac_hex_matches("ab", "ac") is False
    assert hmac_hex_matches("caf\u00e9", "cafe") is False
    assert hmac_hex_matches(123, "123") is False
    assert hmac_hex_matches(None, "ab") is False


def test_non_ascii_receipt_mac_is_mismatch(tmp_path: Path):
    path = write_receipt({"ok": True, "bundle_hash": "abc", "kind": "bundle"}, tmp_path / "r.json", hmac_key="k")
    data = json.loads(path.read_text(encoding="utf-8"))
    data["attestation"]["mac"] = "not-hex-\u00e9"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ReceiptMismatchError, match="MAC"):
        verify_receipt(path, hmac_key="k")


def test_non_ascii_pack_mac_is_mismatch():
    meta = {
        "content_digest": "abc",
        "attestation": {"alg": "hmac-sha256", "mac": "bad-\u00e9", "version": 1},
    }
    with pytest.raises(ChainIntegrityError, match="MAC"):
        verify_pack_meta(meta, content_digest="abc", hmac_key="k")


def test_non_ascii_heal_mac_is_divergence(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SAGE_HEAL_KEY", "heal-key")
    with SageRecorder("h", register_trace=False) as rec:
        with rec.tool_call("t"):
            pass
        bundle = rec.finalize()
    cap = HealCapability.issue(bundle, heal_span_id=bundle.spans[0].span_id)
    payload = cap.to_dict()
    payload["mac"] = "bad-\u00e9"
    with pytest.raises(SecurityDivergence, match="MAC"):
        HealCapability.from_dict(payload)
