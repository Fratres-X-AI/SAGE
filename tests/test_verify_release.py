"""scripts/verify_release.py: checksum checks and fail-closed tool handling."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("verify_release", ROOT / "scripts" / "verify_release.py")
vr = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(vr)


def _release(tmp_path: Path) -> Path:
    dist = tmp_path / "dist"
    dist.mkdir()
    for name, data in (("sage_incident_bundles-9.9.9-py3-none-any.whl", b"wheel"),
                       ("sage_incident_bundles-9.9.9.tar.gz", b"sdist"),
                       ("sbom.spdx.json", b"{}")):
        (dist / name).write_bytes(data)
    sums = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in dist.iterdir()}
    (dist / "SHA256SUMS.json").write_text(json.dumps(sums), encoding="utf-8")
    return dist


def test_clean_checksums_pass(tmp_path: Path) -> None:
    assert vr.check_checksums(_release(tmp_path)) == []


def test_altered_or_missing_file_fails(tmp_path: Path) -> None:
    dist = _release(tmp_path)
    (dist / "sage_incident_bundles-9.9.9-py3-none-any.whl").write_bytes(b"tampered")
    (dist / "sbom.spdx.json").unlink()
    problems = vr.check_checksums(dist)
    assert any("SHA-256 mismatch" in p for p in problems)
    assert any("missing" in p for p in problems)


def test_missing_sums_is_setup_error(tmp_path: Path) -> None:
    dist = _release(tmp_path)
    (dist / "SHA256SUMS.json").unlink()
    with pytest.raises(vr.SetupError):
        vr.check_checksums(dist)


def test_sigstore_identity_is_pinned_to_release_workflow_and_tag(tmp_path: Path) -> None:
    artifact = tmp_path / "x.whl"
    cmd = vr.sigstore_command(artifact, repo="Fratres-X-AI/SAGE", tag="v2.3.0")
    identity = cmd[cmd.index("--cert-identity") + 1]
    assert identity == "https://github.com/Fratres-X-AI/SAGE/.github/workflows/release.yml@refs/tags/v2.3.0"
    assert cmd[cmd.index("--cert-oidc-issuer") + 1] == vr.OIDC_ISSUER
    assert cmd[cmd.index("--bundle") + 1].endswith("x.whl.sigstore.json")


def test_skipped_checks_are_reported_as_skipped_not_passed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = vr.main([str(_release(tmp_path)), "--tag", "v9.9.9", "--skip", "sigstore", "--skip", "provenance"])
    out = json.loads(capsys.readouterr().out)
    assert code == 0
    assert out["checks"]["sigstore"] == "skipped" and out["checks"]["provenance"] == "skipped"
    assert out["checks"]["checksums"]["ok"] is True


def test_missing_tool_is_setup_exit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(vr.shutil, "which", lambda _name: None)
    code = vr.main([str(_release(tmp_path)), "--tag", "v9.9.9", "--skip", "sigstore"])
    out = json.loads(capsys.readouterr().out)
    assert code == 2
    assert "gh" in out["checks"]["provenance"]["setup_error"]
