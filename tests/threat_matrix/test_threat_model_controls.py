"""Executable threat-model matrix — each adversary from THREAT_MODEL.md.

These are security-tool regression gates, not research benches.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sage.blobs import BlobStore
from sage.errors import BlobIntegrityError, ChainIntegrityError
from sage.journal import SPANS_JSONL, verify_journal
from sage.pack import pack_artifact, unpack_artifact
from sage.policy import load_policy
from sage.receipt import verify_receipt
from sage.recorder import SageRecorder
from sage.verify import verify_artifact


ROOT = Path(__file__).resolve().parents[2]


def test_TM01_tamperer_pack_bytes_fail_closed(tmp_path: Path):
    """Adversary: tamperer with pack bytes."""
    with SageRecorder("tm1", blob_store=tmp_path / "b", register_trace=False) as rec:
        with rec.tool_call("t", inputs={"body": "X" * 1500}):
            pass
        path = rec.export(tmp_path / "i.sage.json")
    pack = pack_artifact(path, tmp_path / "p.sage.tar.gz", hmac_key="k")
    raw = bytearray(pack.read_bytes())
    raw[min(80, len(raw) - 1)] ^= 0xFF
    pack.write_bytes(raw)
    with pytest.raises(Exception):
        unpack_artifact(pack, tmp_path / "out", hmac_key="k")


def test_TM02_journal_forger_live_content_fail_closed(tmp_path: Path):
    """Adversary: journal forger on live spans."""
    journal = tmp_path / "j"
    with SageRecorder("tm2", journal_dir=journal, register_trace=False) as rec:
        with rec.tool_call("t", inputs={"x": 1}):
            pass
        lines = (journal / SPANS_JSONL).read_text(encoding="utf-8").splitlines()
        obj = json.loads(lines[0])
        obj["inputs"]["x"] = 42
        (journal / SPANS_JSONL).write_text(
            json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
        )
        with pytest.raises(ChainIntegrityError):
            verify_journal(journal, allow_live=True)


def test_TM03_witness_strip_fails_pack_v2_when_tip_bound(tmp_path: Path):
    """Adversary: witness tip forge breaks custody MAC."""
    with SageRecorder("tm3", register_trace=False) as rec:
        with rec.tool_call("t"):
            pass
        path = rec.export(tmp_path / "i.sage.json")
    pack = pack_artifact(path, tmp_path / "p.sage.tar.gz", hmac_key="k", pack_version=2)
    report = verify_artifact(pack, hmac_key="k", check_witness=True, witness_key="k")
    meta = dict(report["pack"])
    meta["witness_tip"] = "0" * 64
    from sage.pack import verify_pack_meta

    with pytest.raises(ChainIntegrityError, match="MAC"):
        verify_pack_meta(meta, content_digest=meta["content_digest"], hmac_key="k")


def test_TM04_live_carcass_refused_by_strict_policy(tmp_path: Path):
    """Adversary: live-carcass presenter."""
    journal = tmp_path / "live"
    with SageRecorder("tm4", journal_dir=journal, register_trace=False) as rec:
        with rec.tool_call("t"):
            pass
        with pytest.raises(ChainIntegrityError, match="live|policy"):
            verify_artifact(
                journal,
                require_sealed=True,
                policy=load_policy(ROOT / "policies" / "strict.json"),
                check_blobs=False,
            )
        rec.finalize()


def test_TM05_secret_leaker_redacted(tmp_path: Path):
    """Adversary: secret leaker via export."""
    with SageRecorder("tm5", blob_store=tmp_path / "b", register_trace=False) as rec:
        with rec.tool_call("t", inputs={"api_key": "sk-threatmatrix99"}):
            pass
        bundle = rec.finalize()
    assert "sk-threatmatrix99" not in json.dumps(bundle.to_dict())


def test_TM06_cas_path_traversal_blocked(tmp_path: Path):
    """Adversary: CAS path escape."""
    store = BlobStore(tmp_path / "blobs")
    with pytest.raises(BlobIntegrityError):
        store.exists("../etc/passwd")


def test_TM07_unsigned_receipt_refused(tmp_path: Path):
    """Adversary: forged unsigned receipt."""
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"ok": True, "format": "sage.verify.receipt.v1"}), encoding="utf-8")
    with pytest.raises(ChainIntegrityError, match="unsigned|HMAC"):
        verify_receipt(p)


def test_TM08_quarantine_leaves_dest_clean_on_bad_hmac(tmp_path: Path):
    """Quarantine: failed verify must not promote into out_dir."""
    with SageRecorder("tm8", register_trace=False) as rec:
        with rec.tool_call("t"):
            pass
        path = rec.export(tmp_path / "i.sage.json")
    pack = pack_artifact(path, tmp_path / "p.sage.tar.gz", hmac_key="good")
    dest = tmp_path / "final_out"
    with pytest.raises(ChainIntegrityError):
        unpack_artifact(pack, dest, hmac_key="bad", quarantine=True)
    assert not dest.exists()


def test_TM09_tofu_signer_refused_without_pin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Adversary: TOFU signer — embedded pubkey alone must not satisfy require_signature."""
    from sage.signing import generate_keypair, signing_available

    if not signing_available():
        pytest.skip("cryptography not installed")
    kp = generate_keypair()
    monkeypatch.setenv("SAGE_SIGN_PRIVATE_KEY", kp["private_key"])
    monkeypatch.delenv("SAGE_SIGN_PUBLIC_KEY", raising=False)
    with SageRecorder("tm9", register_trace=False) as rec:
        with rec.tool_call("t"):
            pass
        path = rec.export(tmp_path / "i.sage.json")
    pack = pack_artifact(path, tmp_path / "p.sage.tar.gz", hmac_key="k", sign=True)
    with pytest.raises(ChainIntegrityError, match="pinned|TOFU"):
        verify_artifact(pack, hmac_key="k", require_signature=True)
    # Honest pin accepts.
    report = verify_artifact(
        pack, hmac_key="k", require_signature=True, public_key=kp["public_key"]
    )
    assert report["ok"] and report.get("pack_signature_pinned")
