from __future__ import annotations

import json
from pathlib import Path

from sage import __version__, verify_artifact
from sage.cli import build_parser
from sage.handoff import create_handoff
from sage.policy import load_policy
from sage.recorder import SageRecorder
from sage.version import FORMATS, STABLE_PUBLIC_API, version_report


ROOT = Path(__file__).resolve().parents[1]


def test_version_is_2():
    assert __version__.startswith("2.")
    report = version_report()
    assert report["formats"]["pack"] == "sage.pack.v2"
    assert "sage.verify_artifact" in STABLE_PUBLIC_API


def test_strict_policy_file_exists_and_loads():
    pol = load_policy(ROOT / "policies" / "strict.json")
    assert pol.policy_id == "strict"
    assert pol.require_pack_v2
    assert pol.require_witness_hmac


def test_cli_version():
    parser = build_parser()
    args = parser.parse_args(["version"])
    assert args.func(args) == 0


def test_end_to_end_strict_security_path(tmp_path: Path):
    with SageRecorder("v2", blob_store=tmp_path / "b", register_trace=False) as rec:
        with rec.tool_call("t", inputs={"api_key": "sk-v2secret99", "body": "Y" * 2048}):
            pass
        path = rec.export(tmp_path / "i.sage.json")
    kit = create_handoff(path, tmp_path / "kit", hmac_key="v2-key")
    report = verify_artifact(
        kit / "evidence.sage.tar.gz",
        hmac_key="v2-key",
        check_witness=True,
        witness_key="v2-key",
        policy=load_policy(ROOT / "policies" / "strict.json"),
    )
    assert report["ok"]
    assert report["pack"]["format"] == FORMATS["pack"]
    assert (kit / "HANDOFF.md").exists()
    assert json.loads((kit / "policy.json").read_text(encoding="utf-8"))["format"] == FORMATS["policy"]


def test_sbom_script(tmp_path: Path):
    import subprocess
    import sys

    out = tmp_path / "sbom.json"
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "generate_sbom.py"), str(out)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["packages"][0]["licenseDeclared"] == "FSL-1.1-ALv2"
    assert data["files"]
