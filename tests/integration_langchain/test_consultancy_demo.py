"""End-to-end consultancy demonstration through real LangChain: persistent, shareable, verifiable."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

pytest.importorskip("langchain_core")

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "examples" / "consultancy_demo.py"
SECRET_MARKERS = ("demoFICTIONAL",)


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("SAGE_")}
    env["LANGCHAIN_TRACING_V2"] = "false"
    env["LANGSMITH_TRACING"] = "false"
    return subprocess.run([sys.executable, str(DEMO), *args], capture_output=True, text=True, env=env, timeout=300)


def _scan(root: Path, tmp: Path) -> str:
    texts = []
    for path in root.rglob("*"):
        if path.is_file() and path.name.endswith(".tar.gz"):
            extract = tmp / f"x-{path.parent.name}"
            with tarfile.open(path) as tar:
                tar.extractall(extract, filter="data")
            texts.append(_scan(extract, tmp))
        elif path.is_file():
            texts.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(texts)


@pytest.mark.parametrize(
    ("scenario", "mode", "workflow"),
    [
        ("success", "sync", "succeeded"),
        ("tool-error", "sync", "failed"),
        ("tool-timeout", "sync", "failed"),
        ("success", "async", "succeeded"),
        ("tool-error", "async", "failed"),
        ("tool-timeout", "async", "failed"),
    ],
)
def test_demo_produces_verified_persistent_kit(tmp_path: Path, scenario: str, mode: str, workflow: str) -> None:
    out = tmp_path / "run"
    proc = _run("--scenario", scenario, "--mode", mode, "--out", str(out))
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert result["workflow_outcome"] == workflow
    assert result["capture_completeness"] == "complete"
    assert result["evidence_verification"] == "passed"

    kit = out / "handoff"
    expected = {"evidence.sage.tar.gz", "policy.json", "verify.receipt.json", "verify_handoff.py",
                "HANDOFF.md", "INCIDENT_SUMMARY.md", "build_record.json"}
    assert expected <= {p.name for p in kit.iterdir()}
    assert not any("private" in p.name or p.name.endswith(".key") for p in kit.rglob("*"))
    assert (out / "keys" / "hmac.key").exists()

    summary = (kit / "INCIDENT_SUMMARY.md").read_text(encoding="utf-8")
    assert f"**Workflow outcome:** {workflow}" in summary
    assert "**Capture completeness:** complete" in summary
    assert "**Evidence verification:** passed" in summary
    assert "FakeListChatModel" in summary
    if scenario == "tool-timeout":
        assert "`TimeoutError`" in summary
    if scenario == "tool-error":
        assert "`AccountServiceError`" in summary

    record = json.loads((kit / "build_record.json").read_text(encoding="utf-8"))
    assert record["scenario"] == scenario and record["mode"] == mode and record["data"].startswith("synthetic")

    shared = _scan(kit, tmp_path)
    for marker in SECRET_MARKERS:
        assert marker not in shared


def test_relocated_kit_verifies_with_separately_provisioned_keys(tmp_path: Path) -> None:
    out = tmp_path / "run"
    assert _run("--scenario", "tool-error", "--out", str(out)).returncode == 0
    recipient = tmp_path / "recipient" / "kit"
    shutil.copytree(out / "handoff", recipient)
    env = {k: v for k, v in os.environ.items() if not k.startswith("SAGE_")}
    env["SAGE_PACK_KEY"] = (out / "keys" / "hmac.key").read_text(encoding="utf-8")
    pin = (out / "keys" / "ed25519.public.txt").read_text(encoding="utf-8")
    ok = subprocess.run([sys.executable, str(recipient / "verify_handoff.py"), f"--public-key={pin}"],
                        capture_output=True, text=True, env=env, cwd=tmp_path, timeout=120)
    assert ok.returncode == 0, ok.stderr
    no_pin = subprocess.run([sys.executable, str(recipient / "verify_handoff.py")],
                            capture_output=True, text=True, env=env, cwd=tmp_path, timeout=120)
    assert no_pin.returncode == 2


def test_demo_refuses_to_overwrite_a_run(tmp_path: Path) -> None:
    out = tmp_path / "run"
    assert _run("--scenario", "success", "--out", str(out)).returncode == 0
    again = _run("--scenario", "success", "--out", str(out))
    assert again.returncode == 2
    assert "already contains files" in again.stderr
