"""v2.1 layer: quarantine unpack, optional Ed25519, sage doctor."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from sage.doctor import run_doctor
from sage.errors import ChainIntegrityError
from sage.pack import pack_artifact, unpack_artifact
from sage.recorder import SageRecorder
from sage.signing import generate_keypair, signing_available
from sage.verify import verify_artifact


def test_doctor_quick_ok():
    report = run_doctor(deep=False)
    assert report["ok"] is True
    assert report["sage_version"]
    names = {c["name"] for c in report["checks"]}
    assert "python>=3.10" in names
    assert "import_core" in names


def test_doctor_deep_mini_loop():
    report = run_doctor(deep=True)
    assert report["ok"] is True
    by_name = {c["name"]: c for c in report["checks"]}
    assert by_name["mini_verify_loop"]["ok"] is True


def test_quarantine_unpack_promotes_on_success(tmp_path: Path):
    with SageRecorder("q1", register_trace=False) as rec:
        with rec.tool_call("t", inputs={"x": 1}):
            pass
        path = rec.export(tmp_path / "i.sage.json")
    pack = pack_artifact(path, tmp_path / "p.sage.tar.gz", hmac_key="k")
    dest = tmp_path / "promoted"
    journal = unpack_artifact(pack, dest, hmac_key="k", quarantine=True)
    assert dest.exists()
    assert journal.exists()
    assert (dest / "sage_artifact" / "pack.json").exists()


def test_quarantine_does_not_clobber_existing_on_fail(tmp_path: Path):
    with SageRecorder("q2", register_trace=False) as rec:
        with rec.tool_call("t"):
            pass
        path = rec.export(tmp_path / "i.sage.json")
    pack = pack_artifact(path, tmp_path / "p.sage.tar.gz", hmac_key="good")
    dest = tmp_path / "keep_me"
    dest.mkdir()
    marker = dest / "marker.txt"
    marker.write_text("preserve", encoding="utf-8")
    with pytest.raises(ChainIntegrityError):
        unpack_artifact(pack, dest, hmac_key="bad", quarantine=True)
    assert marker.read_text(encoding="utf-8") == "preserve"


@pytest.mark.skipif(not signing_available(), reason="cryptography not installed")
def test_ed25519_pack_sign_and_verify(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    kp = generate_keypair()
    monkeypatch.setenv("SAGE_SIGN_PRIVATE_KEY", kp["private_key"])
    monkeypatch.setenv("SAGE_SIGN_PUBLIC_KEY", kp["public_key"])
    with SageRecorder("s1", register_trace=False) as rec:
        with rec.tool_call("t"):
            pass
        path = rec.export(tmp_path / "i.sage.json")
    pack = pack_artifact(path, tmp_path / "p.sage.tar.gz", hmac_key="k", sign=True)
    report = verify_artifact(pack, hmac_key="k", require_signature=True)
    assert report["ok"] is True
    dest = tmp_path / "out"
    unpack_artifact(pack, dest, hmac_key="k", require_signature=True)
    meta = json.loads((dest / "sage_artifact" / "pack.json").read_text(encoding="utf-8"))
    assert meta.get("signature", {}).get("alg") == "ed25519"


@pytest.mark.skipif(not signing_available(), reason="cryptography not installed")
def test_ed25519_require_signature_without_sig_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SAGE_SIGN_PUBLIC_KEY", generate_keypair()["public_key"])
    with SageRecorder("s2", register_trace=False) as rec:
        with rec.tool_call("t"):
            pass
        path = rec.export(tmp_path / "i.sage.json")
    pack = pack_artifact(path, tmp_path / "p.sage.tar.gz", hmac_key="k", sign=False)
    with pytest.raises(ChainIntegrityError, match="signature"):
        unpack_artifact(pack, tmp_path / "out", hmac_key="k", require_signature=True)


@pytest.mark.skipif(not signing_available(), reason="cryptography not installed")
def test_ed25519_require_signature_refuses_tofu(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    kp = generate_keypair()
    monkeypatch.setenv("SAGE_SIGN_PRIVATE_KEY", kp["private_key"])
    monkeypatch.delenv("SAGE_SIGN_PUBLIC_KEY", raising=False)
    with SageRecorder("s2b", register_trace=False) as rec:
        with rec.tool_call("t"):
            pass
        path = rec.export(tmp_path / "i.sage.json")
    pack = pack_artifact(path, tmp_path / "p.sage.tar.gz", hmac_key="k", sign=True)
    with pytest.raises(ChainIntegrityError, match="pinned|TOFU"):
        unpack_artifact(pack, tmp_path / "out", hmac_key="k", require_signature=True)
    # Escape hatch still works for compatibility.
    unpack_artifact(
        pack, tmp_path / "out_tofu", hmac_key="k", require_signature=True, allow_tofu_signature=True
    )


@pytest.mark.skipif(not signing_available(), reason="cryptography not installed")
def test_ed25519_bad_sig_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    kp = generate_keypair()
    other = generate_keypair()
    monkeypatch.setenv("SAGE_SIGN_PRIVATE_KEY", kp["private_key"])
    monkeypatch.delenv("SAGE_SIGN_PUBLIC_KEY", raising=False)
    with SageRecorder("s3", register_trace=False) as rec:
        with rec.tool_call("t"):
            pass
        path = rec.export(tmp_path / "i.sage.json")
    pack = pack_artifact(path, tmp_path / "p.sage.tar.gz", hmac_key="k", sign=True)
    # Pinned wrong key must beat embedded TOFU public_key in the signature block.
    with pytest.raises(ChainIntegrityError, match="signature"):
        unpack_artifact(
            pack,
            tmp_path / "out",
            hmac_key="k",
            require_signature=True,
            public_key=other["public_key"],
        )


@pytest.mark.skipif(signing_available(), reason="only when cryptography missing")
def test_sign_without_crypto_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SAGE_SIGN_PRIVATE_KEY", "not-a-real-key")
    with SageRecorder("s4", register_trace=False) as rec:
        with rec.tool_call("t"):
            pass
        path = rec.export(tmp_path / "i.sage.json")
    with pytest.raises(ChainIntegrityError, match="sign"):
        pack_artifact(path, tmp_path / "p.sage.tar.gz", hmac_key="k", sign=True)
