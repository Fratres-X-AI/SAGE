"""Handoff kits: consistent policy enforcement, staged promotion, and receipt binding."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from sage import SageRecorder
from sage.handoff import HandoffSetupError, create_handoff
from sage.policy import VerifyPolicy, load_policy
from sage.version import __version__

ROOT = Path(__file__).resolve().parents[1]
HMAC = "handoff-test-hmac-key"


def _bundle(tmp: Path, name: str = "run") -> Path:
    rec = SageRecorder(title=name, trace_id=f"trace-{name}", blob_store=tmp / f"{name}-blobs")
    with rec:
        with rec.chain("flow", inputs={"q": "hello"}) as chain:
            with rec.tool_call("lookup", inputs={"id": 1}) as tool:
                tool.set_output(rows=["x" * 2000])
            chain.set_output(answer="done")
    return rec.export(tmp / f"{name}.sage.json")


def _helper(kit: Path, *args: str, env_extra: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("SAGE_")}
    env.update(env_extra or {})
    return subprocess.run(
        [sys.executable, str(kit / "verify_handoff.py"), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )


def test_clean_kit_verifies_and_binds_receipt(tmp_path: Path) -> None:
    kit = create_handoff(_bundle(tmp_path), tmp_path / "kit", hmac_key=HMAC)
    proc = _helper(kit, env_extra={"SAGE_PACK_KEY": HMAC})
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["evidence_verified"] and out["receipt_bound"] and out["receipt_mac_verified"]
    receipt = json.loads((kit / "verify.receipt.json").read_text(encoding="utf-8"))
    assert receipt["sage_version"] == out["sage_version"] == __version__


def test_wrong_hmac_key_fails_and_missing_key_is_setup_error(tmp_path: Path) -> None:
    kit = create_handoff(_bundle(tmp_path), tmp_path / "kit", hmac_key=HMAC)
    assert _helper(kit, env_extra={"SAGE_PACK_KEY": "wrong"}).returncode == 1
    assert _helper(kit).returncode == 2


def test_receipt_from_another_artifact_is_rejected(tmp_path: Path) -> None:
    kit_a = create_handoff(_bundle(tmp_path, "a"), tmp_path / "kit-a", hmac_key=HMAC)
    kit_b = create_handoff(_bundle(tmp_path, "b"), tmp_path / "kit-b", hmac_key=HMAC)
    shutil.copy2(kit_b / "verify.receipt.json", kit_a / "verify.receipt.json")
    proc = _helper(kit_a, env_extra={"SAGE_PACK_KEY": HMAC})
    assert proc.returncode == 1
    assert json.loads(proc.stderr)["stage"] == "receipt"


def test_changed_policy_cannot_pose_as_recorded_policy(tmp_path: Path) -> None:
    kit = create_handoff(_bundle(tmp_path), tmp_path / "kit", hmac_key=HMAC)
    pol = json.loads((kit / "policy.json").read_text(encoding="utf-8"))
    pol["require_witness"] = False
    pol["require_witness_hmac"] = False
    (kit / "policy.json").write_text(json.dumps(pol), encoding="utf-8")
    proc = _helper(kit, env_extra={"SAGE_PACK_KEY": HMAC})
    assert proc.returncode == 1
    assert "policy_digest" in json.loads(proc.stderr).get("fields", [])


def test_missing_receipt_is_rejected(tmp_path: Path) -> None:
    kit = create_handoff(_bundle(tmp_path), tmp_path / "kit", hmac_key=HMAC)
    (kit / "verify.receipt.json").unlink()
    assert _helper(kit, env_extra={"SAGE_PACK_KEY": HMAC}).returncode == 1


def test_strict_policy_is_never_softened_without_key(tmp_path: Path) -> None:
    strict = load_policy(ROOT / "policies" / "strict.json")
    before = strict.to_dict()
    with pytest.raises(HandoffSetupError):
        create_handoff(_bundle(tmp_path), tmp_path / "kit", policy=strict)
    assert strict.to_dict() == before
    assert not (tmp_path / "kit").exists()
    assert not list(tmp_path.glob(".kit.staging-*"))


def test_explicit_policy_object_is_not_mutated(tmp_path: Path) -> None:
    pol = VerifyPolicy(policy_id="custom", require_witness=True, require_pack_hmac=True)
    before = pol.to_dict()
    kit = create_handoff(_bundle(tmp_path), tmp_path / "kit", hmac_key=HMAC, policy=pol)
    assert pol.to_dict() == before
    assert json.loads((kit / "policy.json").read_text(encoding="utf-8")) == before


def test_refuses_to_overwrite_completed_kit(tmp_path: Path) -> None:
    src = _bundle(tmp_path)
    kit = create_handoff(src, tmp_path / "kit", hmac_key=HMAC)
    marker = (kit / "verify.receipt.json").read_bytes()
    with pytest.raises(HandoffSetupError):
        create_handoff(src, kit, hmac_key=HMAC)
    assert (kit / "verify.receipt.json").read_bytes() == marker


def test_failed_verification_leaves_no_kit(tmp_path: Path) -> None:
    pol = VerifyPolicy(policy_id="needs-spans", min_span_count=50)
    with pytest.raises(Exception):
        create_handoff(_bundle(tmp_path), tmp_path / "kit", hmac_key=HMAC, policy=pol)
    assert not (tmp_path / "kit").exists()
    assert not list(tmp_path.glob(".kit.staging-*"))


def test_failed_rebuild_does_not_modify_existing_valid_kit(tmp_path: Path) -> None:
    src = _bundle(tmp_path)
    kit = create_handoff(src, tmp_path / "kit", hmac_key=HMAC)
    before = {p.name: p.read_bytes() for p in kit.iterdir()}
    with pytest.raises(Exception):
        create_handoff(src, kit, hmac_key=HMAC, policy=VerifyPolicy(min_span_count=99), overwrite=True)
    assert {p.name: p.read_bytes() for p in kit.iterdir()} == before


signing = pytest.importorskip("sage.signing")


@pytest.mark.skipif(not signing.signing_available(), reason="cryptography not installed")
class TestPinnedSignatureHandoff:
    def _signed_kit(self, tmp_path: Path) -> tuple[Path, dict[str, str]]:
        kp = signing.generate_keypair()
        pol = VerifyPolicy(
            policy_id="signed",
            require_witness=True,
            require_witness_hmac=True,
            require_pack_hmac=True,
            require_pack_v2=True,
            require_pack_signature=True,
        )
        kit = create_handoff(
            _bundle(tmp_path),
            tmp_path / "kit",
            hmac_key=HMAC,
            policy=pol,
            public_key=kp["public_key"],
            private_key=kp["private_key"],
            sign=True,
        )
        return kit, kp

    def test_correct_pin_verifies(self, tmp_path: Path) -> None:
        kit, kp = self._signed_kit(tmp_path)
        proc = _helper(kit, f"--public-key={kp['public_key']}", env_extra={"SAGE_PACK_KEY": HMAC})
        assert proc.returncode == 0, proc.stderr
        out = json.loads(proc.stdout)
        assert out["signature_pinned"] is True
        assert out["pinned_key_fingerprint"] == hashlib.sha256(signing._b64d(kp["public_key"])).hexdigest()

    def test_wrong_or_absent_pin_fails(self, tmp_path: Path) -> None:
        kit, _kp = self._signed_kit(tmp_path)
        other = signing.generate_keypair()["public_key"]
        wrong = _helper(kit, f"--public-key={other}", env_extra={"SAGE_PACK_KEY": HMAC})
        assert wrong.returncode == 1
        assert json.loads(wrong.stderr)["error"].rstrip().endswith("pinned public key")
        assert _helper(kit, env_extra={"SAGE_PACK_KEY": HMAC}).returncode == 2

    def test_missing_cryptography_is_a_setup_error_with_recipient_hint(self, tmp_path: Path) -> None:
        kit, kp = self._signed_kit(tmp_path)
        blocker = tmp_path / "block_crypto"
        blocker.mkdir()
        (blocker / "sitecustomize.py").write_text("import sys\nsys.modules['cryptography'] = None\n", encoding="utf-8")
        proc = _helper(kit, f"--public-key={kp['public_key']}",
                       env_extra={"SAGE_PACK_KEY": HMAC, "PYTHONPATH": os.pathsep.join([str(blocker), *sys.path])})
        assert proc.returncode == 2, proc.stderr
        err = json.loads(proc.stderr)
        assert err["stage"] == "setup"
        assert "[sign]" in err["error"] and "-e" not in err["error"]

    def test_pin_that_starts_with_dash_is_accepted(self, tmp_path: Path) -> None:
        kp = next(k for k in iter(signing.generate_keypair, None) if k["public_key"].startswith("-"))
        pol = VerifyPolicy(policy_id="signed", require_pack_hmac=True, require_pack_signature=True)
        kit = create_handoff(_bundle(tmp_path), tmp_path / "kit", hmac_key=HMAC, policy=pol,
                             public_key=kp["public_key"], private_key=kp["private_key"], sign=True)
        proc = _helper(kit, f"--public-key={kp['public_key']}", env_extra={"SAGE_PACK_KEY": HMAC})
        assert proc.returncode == 0, proc.stderr

    def test_handoff_refuses_signature_policy_without_pin(self, tmp_path: Path) -> None:
        pol = VerifyPolicy(policy_id="signed", require_pack_signature=True)
        env_pin = os.environ.pop("SAGE_SIGN_PUBLIC_KEY", None)
        try:
            with pytest.raises(HandoffSetupError):
                create_handoff(_bundle(tmp_path), tmp_path / "kit", hmac_key=HMAC, policy=pol)
        finally:
            if env_pin is not None:
                os.environ["SAGE_SIGN_PUBLIC_KEY"] = env_pin
        assert not (tmp_path / "kit").exists()
