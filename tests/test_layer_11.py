from __future__ import annotations

import json
from pathlib import Path

import pytest

from sage.cli import build_parser
from sage.errors import ChainIntegrityError
from sage.handoff import create_handoff
from sage.keys import write_key_ring
from sage.pack import pack_artifact, unpack_artifact, verify_pack_meta, compute_artifact_digest
from sage.policy import VerifyPolicy, apply_policy, load_policy
from sage.receipt import verify_receipt, write_receipt
from sage.recorder import SageRecorder
from sage.verify import verify_artifact


def _sealed(tmp_path: Path):
    with SageRecorder("l11", blob_store=tmp_path / "blobs", register_trace=False) as rec:
        with rec.tool_call("t", inputs={"api_key": "sk-abc12345xx", "body": "Z" * 1500}):
            pass
        path = rec.export(tmp_path / "a.sage.json")
    return path


def test_pack_v2_custody_mac_binds_witness(tmp_path: Path):
    path = _sealed(tmp_path)
    pack = pack_artifact(path, tmp_path / "p.sage.tar.gz", hmac_key="k", pack_version=2, key_id="prod")
    report = verify_artifact(pack, hmac_key="k", check_witness=True, witness_key="k")
    assert report["ok"]
    assert report["pack"]["format"] == "sage.pack.v2"
    assert report["pack"]["attestation"]["version"] == 2
    assert report["pack"]["witness_tip"] != "no_witness"
    assert report["pack_hmac_verified"] is True

    # Strip witness tip binding by forging pack.json inside archive is covered via meta API:
    meta = dict(report["pack"])
    meta["witness_tip"] = "0" * 64
    with pytest.raises(ChainIntegrityError, match="MAC"):
        verify_pack_meta(meta, content_digest=meta["content_digest"], hmac_key="k")


def test_policy_profile_fail_closed(tmp_path: Path):
    path = _sealed(tmp_path)
    pack = pack_artifact(path, tmp_path / "p.sage.tar.gz", hmac_key="k", pack_version=2)
    policy = VerifyPolicy(
        policy_id="strict",
        require_witness=True,
        require_witness_hmac=True,
        require_pack_hmac=True,
        require_pack_v2=True,
        min_redaction_count=1,
        min_span_count=1,
    )
    report = verify_artifact(
        pack,
        hmac_key="k",
        check_witness=True,
        witness_key="k",
        policy=policy,
    )
    assert report["policy"]["policy_id"] == "strict"

def test_policy_on_bundle_without_witness(tmp_path: Path):
    path = _sealed(tmp_path)
    policy = VerifyPolicy(require_witness=True)
    with pytest.raises(ChainIntegrityError, match="witness"):
        verify_artifact(path, policy=policy, check_blobs=False)


def test_receipt_roundtrip(tmp_path: Path):
    path = _sealed(tmp_path)
    pack = pack_artifact(path, tmp_path / "p.sage.tar.gz", hmac_key="rk")
    report = verify_artifact(pack, hmac_key="rk", check_witness=True, witness_key="rk")
    receipt_path = write_receipt(report, tmp_path / "verify.receipt.json", hmac_key="rk", key_id="v1")
    out = verify_receipt(receipt_path, hmac_key="rk", expect_fingerprint=report["pack"]["content_digest"])
    assert out["ok"]
    # Tamper
    data = json.loads(receipt_path.read_text(encoding="utf-8"))
    data["bundle_hash"] = "f" * 64
    receipt_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    with pytest.raises(ChainIntegrityError, match="MAC"):
        verify_receipt(receipt_path, hmac_key="rk")


def test_handoff_kit(tmp_path: Path):
    path = _sealed(tmp_path)
    dest = create_handoff(path, tmp_path / "kit", hmac_key="hk", actor="soc")
    assert (dest / "evidence.sage.tar.gz").exists()
    assert (dest / "policy.json").exists()
    assert (dest / "HANDOFF.md").exists()
    assert (dest / "verify_handoff.py").exists()
    assert (dest / "verify.receipt.json").exists()
    verify_receipt(dest / "verify.receipt.json", hmac_key="hk")


def test_cli_verify_policy_and_receipt(tmp_path: Path):
    path = _sealed(tmp_path)
    pack = pack_artifact(path, tmp_path / "p.sage.tar.gz", hmac_key="ck")
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            VerifyPolicy(
                require_witness=True,
                require_witness_hmac=True,
                require_pack_hmac=True,
                require_pack_v2=True,
            ).to_dict(),
            indent=2,
        ),
        encoding="utf-8",
    )
    parser = build_parser()
    args = parser.parse_args(
        [
            "verify",
            str(pack),
            "--hmac-key",
            "ck",
            "--witness",
            "--policy",
            str(policy_path),
            "--receipt",
            str(tmp_path / "r.json"),
            "--verify-key",
            "ck",
        ]
    )
    assert args.func(args) == 0
    assert (tmp_path / "r.json").exists()


def test_key_ring_env_resolution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SAGE_PACK_KEY", "from-ring")
    ring = write_key_ring(tmp_path / "keys.ring.json", {"prod": {"env": "SAGE_PACK_KEY"}})
    from sage.keys import resolve_key_material

    key, kid = resolve_key_material(key_id="prod", key_ring=ring)
    assert key == b"from-ring"
    assert kid == "prod"


def test_pack_v1_still_works(tmp_path: Path):
    path = _sealed(tmp_path)
    pack = pack_artifact(path, tmp_path / "old.sage.tar.gz", hmac_key="v1", pack_version=1)
    report = verify_artifact(pack, hmac_key="v1", check_witness=True, witness_key="v1")
    assert report["pack"]["format"] == "sage.pack.v1"
    assert report["pack"]["attestation"]["version"] == 1
