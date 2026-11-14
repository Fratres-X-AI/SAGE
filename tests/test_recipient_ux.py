"""Recipient UX: specific error types, key-file options, `sage key fingerprint`, `sage handoff verify`,
the single-file verifier, and the pure-Python Ed25519 fallback it relies on."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from sage import SageRecorder
from sage._ed25519_verify import _L, verify as pure_verify
from sage.errors import ChainIntegrityError, PolicyViolationError, ReceiptMismatchError, SignatureMismatchError
from sage.handoff import create_handoff
from sage.policy import VerifyPolicy
from sage.version import __version__

ROOT = Path(__file__).resolve().parents[1]
HMAC = "recipient-ux-hmac-key"
signing = pytest.importorskip("sage.signing")
needs_crypto = pytest.mark.skipif(not signing.signing_available(), reason="cryptography not installed")


def _bundle(tmp: Path) -> Path:
    rec = SageRecorder(title="ux", trace_id="trace-ux", blob_store=tmp / "blobs")
    with rec:
        with rec.chain("flow", inputs={"q": "hello"}) as chain:
            with rec.tool_call("lookup", inputs={"id": 1}) as tool:
                tool.set_output(rows=["x" * 2000])
            chain.set_output(answer="done")
    return rec.export(tmp / "ux.sage.json")


def _clean_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if not k.startswith("SAGE_")}


def _run(cmd: list[str]) -> tuple[int, dict]:
    proc = subprocess.run(cmd, capture_output=True, text=True, env=_clean_env(), timeout=120)
    text = proc.stdout if proc.returncode == 0 else proc.stderr
    return proc.returncode, json.loads(text)


@pytest.fixture()
def signed_kit(tmp_path: Path):
    if not signing.signing_available():
        pytest.skip("cryptography not installed")
    kp = signing.generate_keypair()
    pol = VerifyPolicy(policy_id="signed", require_witness=True, require_witness_hmac=True,
                       require_pack_hmac=True, require_pack_v2=True, require_pack_signature=True)
    kit = create_handoff(_bundle(tmp_path), tmp_path / "kit", hmac_key=HMAC, policy=pol,
                         public_key=kp["public_key"], private_key=kp["private_key"], sign=True)
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "hmac.key").write_text(HMAC + "\n", encoding="utf-8")
    (keys / "ed25519.public.txt").write_text(kp["public_key"] + "\n", encoding="utf-8")
    return kit, keys, kp


def _key_args(keys: Path, public: Path | None = None) -> list[str]:
    return ["--hmac-key-file", str(keys / "hmac.key"), "--public-key-file", str(public or keys / "ed25519.public.txt")]


def test_specific_errors_keep_compatibility() -> None:
    for cls in (SignatureMismatchError, ReceiptMismatchError, PolicyViolationError):
        assert issubclass(cls, ChainIntegrityError)


def test_install_hint_names_the_installed_version() -> None:
    hint = signing.install_hint()
    assert __version__ in hint and "<wheel file>" not in hint and "pip install cryptography" in hint


@needs_crypto
def test_key_files_verify_and_fingerprint_command_agrees(signed_kit) -> None:
    kit, keys, kp = signed_kit
    code, out = _run([sys.executable, str(kit / "verify_handoff.py"), *_key_args(keys)])
    assert code == 0, out
    code, fp = _run([sys.executable, "-m", "sage.cli", "key", "fingerprint", str(keys / "ed25519.public.txt")])
    assert code == 0
    expected = hashlib.sha256(signing._b64d(kp["public_key"])).hexdigest()
    assert fp["fingerprint_sha256"] == out["pinned_key_fingerprint"] == expected


def test_key_fingerprint_missing_file_is_setup_exit(tmp_path) -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "sage.cli", "key", "fingerprint", str(tmp_path / "absent.txt")],
        capture_output=True, text=True,
    )
    assert proc.returncode == 2
    err = json.loads(proc.stderr)
    assert err["error_type"] == "FileNotFoundError"
    assert "absent.txt" in err["error"]


def _build_kit(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-m", "sage.cli", "handoff", *args],
                          capture_output=True, text=True, env=env, timeout=120)


def test_handoff_build_reads_key_file_and_env_fallback(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    blobs = str(tmp_path / "blobs")
    key_file = tmp_path / "hmac.key"
    key_file.write_text(HMAC + "\n", encoding="utf-8")

    built = _build_kit([str(bundle), "--out-dir", str(tmp_path / "kit-file"), "--hmac-key-file", str(key_file),
                        "--blob-root", blobs], _clean_env())
    assert built.returncode == 0, built.stderr
    assert HMAC not in built.stdout + built.stderr
    code, out = _run([sys.executable, "-m", "sage.cli", "handoff", "verify", str(tmp_path / "kit-file"),
                      "--hmac-key-file", str(key_file)])
    assert code == 0 and out["ok"] is True

    built = _build_kit([str(bundle), "--out-dir", str(tmp_path / "kit-env"), "--blob-root", blobs],
                       {**_clean_env(), "SAGE_PACK_KEY": HMAC})
    assert built.returncode == 0, built.stderr
    code, _ = _run([sys.executable, "-m", "sage.cli", "handoff", "verify", str(tmp_path / "kit-env"),
                    "--hmac-key-file", str(key_file)])
    assert code == 0


def test_handoff_build_key_file_errors_are_setup_exits(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    empty = tmp_path / "empty.key"
    empty.write_text("\n", encoding="utf-8")
    for extra in (["--hmac-key-file", str(empty)], ["--hmac-key-file", str(tmp_path / "absent.key")],
                  ["--hmac-key-file", str(empty), "--hmac-key", "x"]):
        result = _build_kit([str(bundle), "--out-dir", str(tmp_path / "kit"), *extra], _clean_env())
        assert result.returncode == 2, (extra, result.stderr)
        assert not (tmp_path / "kit").exists()


def test_handoff_help_documents_options_and_verify() -> None:
    proc = subprocess.run([sys.executable, "-m", "sage.cli", "handoff", "--help"],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0
    text = " ".join(proc.stdout.split())
    assert "sage handoff verify" in text and "--hmac-key-file" in text and "SAGE_PACK_KEY" in text
    for phrase in ("HMAC key value", "Verify policy JSON file", "Name recorded in the witness log",
                   "Key id to record"):
        assert phrase in text


def test_handoff_md_documents_pyz_and_mismatch() -> None:
    from sage.handoff import HANDOFF_MD

    assert "sage-verify-<version>.pyz" in HANDOFF_MD
    assert "If the fingerprints differ, stop" in HANDOFF_MD
    assert "`--public-key-file` is needed when" in HANDOFF_MD


@needs_crypto
def test_sage_handoff_verify_subcommand(signed_kit) -> None:
    kit, keys, _kp = signed_kit
    code, out = _run([sys.executable, "-m", "sage.cli", "handoff", "verify", str(kit), *_key_args(keys)])
    assert code == 0 and out["evidence_verified"], out
    code, out = _run([sys.executable, "-m", "sage.cli", "handoff", "verify", str(kit)])
    assert code == 2 and out["stage"] == "setup"


@needs_crypto
def test_wrong_public_key_is_signature_mismatch(signed_kit, tmp_path: Path) -> None:
    kit, keys, _kp = signed_kit
    other = tmp_path / "other.txt"
    other.write_text(signing.generate_keypair()["public_key"], encoding="utf-8")
    code, out = _run([sys.executable, str(kit / "verify_handoff.py"), *_key_args(keys, other)])
    assert code == 1 and out["error_type"] == "SignatureMismatchError"


@needs_crypto
def test_tampered_receipt_is_receipt_mismatch(signed_kit) -> None:
    kit, keys, _kp = signed_kit
    receipt = json.loads((kit / "verify.receipt.json").read_text(encoding="utf-8"))
    receipt["bundle_hash"] = "0" * 64
    (kit / "verify.receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
    code, out = _run([sys.executable, str(kit / "verify_handoff.py"), *_key_args(keys)])
    assert code == 1 and out["stage"] == "receipt" and out["error_type"] == "ReceiptMismatchError"


@needs_crypto
def test_policy_violation_is_reported_by_type(signed_kit) -> None:
    kit, keys, _kp = signed_kit
    pol = json.loads((kit / "policy.json").read_text(encoding="utf-8"))
    pol["min_span_count"] = 99
    (kit / "policy.json").write_text(json.dumps(pol), encoding="utf-8")
    code, out = _run([sys.executable, str(kit / "verify_handoff.py"), *_key_args(keys)])
    assert code == 1 and out["error_type"] == "PolicyViolationError"


def test_unreadable_key_file_is_setup_error(tmp_path: Path) -> None:
    kit = create_handoff(_bundle(tmp_path), tmp_path / "kit", hmac_key=HMAC)
    code, out = _run([sys.executable, str(kit / "verify_handoff.py"), "--hmac-key-file", str(tmp_path / "nope")])
    assert code == 2 and "cannot read key file" in out["error"]


@pytest.fixture(scope="module")
def verifier_pyz(tmp_path_factory) -> Path:
    spec = importlib.util.spec_from_file_location("build_verifier", ROOT / "scripts" / "build_verifier.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod.build(tmp_path_factory.mktemp("pyz"))


@needs_crypto
def test_single_file_verifier_runs_without_any_packages(signed_kit, verifier_pyz, tmp_path: Path) -> None:
    kit, keys, _kp = signed_kit
    isolated = [sys.executable, "-I", "-S", str(verifier_pyz)]
    probe = subprocess.run([sys.executable, "-I", "-S", "-c", "import cryptography"], capture_output=True)
    assert probe.returncode != 0, "isolated interpreter unexpectedly sees cryptography"
    code, out = _run([*isolated, str(kit), *_key_args(keys)])
    assert code == 0 and out["signature_pinned"] is True, out
    other = tmp_path / "other.txt"
    other.write_text(signing.generate_keypair()["public_key"], encoding="utf-8")
    code, out = _run([*isolated, str(kit), *_key_args(keys, other)])
    assert code == 1 and out["error_type"] == "SignatureMismatchError"


def test_single_file_verifier_build_is_reproducible(verifier_pyz, tmp_path: Path) -> None:
    spec = importlib.util.spec_from_file_location("build_verifier2", ROOT / "scripts" / "build_verifier.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    again = mod.build(tmp_path)
    assert again.read_bytes() == verifier_pyz.read_bytes()


RFC8032_PUB = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
RFC8032_SIG = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)


def test_pure_ed25519_rfc8032_vector_and_rejections() -> None:
    assert pure_verify(RFC8032_PUB, b"", RFC8032_SIG)
    assert not pure_verify(RFC8032_PUB, b"x", RFC8032_SIG)
    s = int.from_bytes(RFC8032_SIG[32:], "little")
    malleable = RFC8032_SIG[:32] + (s + _L).to_bytes(32, "little")
    assert not pure_verify(RFC8032_PUB, b"", malleable)
    assert not pure_verify(b"\xff" * 32, b"", RFC8032_SIG)
    assert not pure_verify(RFC8032_PUB[:31], b"", RFC8032_SIG)
    assert not pure_verify(RFC8032_PUB, b"", RFC8032_SIG[:63])


@needs_crypto
def test_pure_ed25519_agrees_with_cryptography() -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    for i in range(20):
        key = Ed25519PrivateKey.generate()
        pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        msg = os.urandom(i * 13)
        sig = key.sign(msg)
        assert pure_verify(pub, msg, sig)
        flipped = bytes([sig[0] ^ 1]) + sig[1:]
        assert not pure_verify(pub, msg, flipped)
