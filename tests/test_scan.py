"""`sage scan`: pre-share leak report with locations and rule ids, never the values."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import _redaction_corpus as corpus
from sage import SageRecorder
from sage.audit import attach_audit_chain, finalize_bundle
from sage.cli import main as cli_main
from sage.pack import pack_artifact
from sage.scan import SCAN_RULES, ScanSetupError, scan_path

ROOT = Path(__file__).resolve().parents[1]
CANARIES = [
    corpus.AWS_ACCESS_KEY_ID,
    corpus.EMAIL,
    corpus.JWT,
    corpus.GITHUB_TOKEN,
    corpus.SLACK_TOKEN,
    corpus.STRIPE_KEY,
    corpus.HIGH_ENTROPY,
    corpus.LOCAL_PATH_WINDOWS,
    corpus.PEM_PRIVATE_KEY,
]


def _cli(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    with pytest.raises(SystemExit) as exc:
        cli_main(argv)
    out, err = capsys.readouterr()
    return int(exc.value.code or 0), out, err


def _assert_no_value_text(text: str) -> None:
    # The local-path canary shares its "C:\Users\" prefix with the real paths the CLI prints.
    assert "pat\\proj" not in text
    for canary in CANARIES:
        if canary == corpus.LOCAL_PATH_WINDOWS:
            continue
        for start in range(0, len(canary) - 7):
            piece = canary[start:start + 8]
            if piece.strip() and not piece.isalpha():
                assert piece not in text, "scan output contains part of a matched value"


def _leaky_recording(tmp_path: Path) -> tuple[Path, Path]:
    """Default recorder (no detectors): provider keys, emails, and paths pass the default rules."""
    rec = SageRecorder(
        title="leaky run",
        trace_id="leaky-trace",
        journal_dir=tmp_path / "j",
        blob_store=tmp_path / "blobs",
        metadata={"owner": corpus.EMAIL, "workdir": corpus.LOCAL_PATH_WINDOWS},
    )
    with rec:
        with rec.llm_call("model", inputs={"prompt": f"use {corpus.AWS_ACCESS_KEY_ID}"}) as llm:
            llm.set_output(text=("long answer " * 200) + corpus.GITHUB_TOKEN)
            span_id = llm.span.span_id
        with rec.tool_call("notify", inputs={"jwt": corpus.JWT, corpus.SLACK_TOKEN: "as a key"}):
            pass
    return rec.export(tmp_path / "bundle.sage.json"), tmp_path / "j"


@pytest.fixture()
def leaky(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, Path]:
    monkeypatch.chdir(tmp_path)
    bundle, journal = _leaky_recording(tmp_path)
    pack = pack_artifact(journal, tmp_path / "e.sage.tar.gz", hmac_key=b"k" * 32)
    return bundle, journal, Path(pack)


def test_pack_findings_have_locations_and_rule_ids(leaky: tuple[Path, Path, Path]) -> None:
    _bundle, _journal, pack = leaky
    report = scan_path(pack)
    assert not report.ok
    rules = report.counts()
    for rule in ("aws_access_key_id", "github_token", "jwt", "slack_token", "email", "local_path"):
        assert rule in rules, f"{rule} not reported"
    aws = next(
        f for f in report.findings
        if f.rule == "aws_access_key_id" and f.member.endswith("spans.jsonl") and f.path == "$.inputs.prompt"
    )
    assert aws.span_id and aws.span_id.startswith("span_") and aws.line == 1
    assert aws.length == len(corpus.AWS_ACCESS_KEY_ID)
    github = [f for f in report.findings if f.rule == "github_token"]
    assert any("/blobs/" in f.member for f in github), "offloaded blob content was not scanned"
    slack_key = next(f for f in report.findings if f.rule == "slack_token")
    assert "<key #" in slack_key.path
    meta = [f for f in report.findings if f.rule in ("email", "local_path") and "manifest" in f.member]
    assert meta and all(f.path.startswith("$.metadata") for f in meta)
    _assert_no_value_text(json.dumps(report.to_dict()))


def test_bundle_and_journal_scans_include_external_blobs(leaky: tuple[Path, Path, Path], tmp_path: Path) -> None:
    bundle, journal, _pack = leaky
    for target in (bundle, journal):
        report = scan_path(target, blob_root=tmp_path / "blobs")
        assert report.blobs_scanned >= 1 and report.blobs_unavailable == 0
        assert any(f.member.startswith("blob:") and f.rule == "github_token" for f in report.findings)


def test_cli_exit_codes_and_json(leaky: tuple[Path, Path, Path], tmp_path: Path, capsys) -> None:
    _bundle, _journal, pack = leaky
    code, out, err = _cli(["scan", str(pack)], capsys)
    assert code == 1
    assert "aws_access_key_id" in out and "Values are never printed" in out
    _assert_no_value_text(out + err)

    code, out, err = _cli(["scan", str(pack), "--json"], capsys)
    assert code == 1
    payload = json.loads(out)
    assert payload["ok"] is False and payload["finding_count"] == len(payload["findings"])
    assert set(payload["findings"][0]) >= {"rule", "member", "path", "length", "sha256_prefix"}
    assert all(len(f["sha256_prefix"]) == 8 for f in payload["findings"])
    _assert_no_value_text(out + err)

    code, out, _err = _cli(["scan", str(pack), "--rule", "card_number", "--json"], capsys)
    assert code == 0 and json.loads(out)["ok"] is True

    code, _out, err = _cli(["scan", str(tmp_path / "missing.sage.json")], capsys)
    assert code == 2 and "does not exist" in err
    code, _out, err = _cli(["scan", str(pack), "--rule", "nope"], capsys)
    assert code == 2 and "unknown scan rule" in err
    not_pack = tmp_path / "notes.txt"
    not_pack.write_text("hello", encoding="utf-8")
    code, _out, _err = _cli(["scan", str(not_pack)], capsys)
    assert code == 2
    corrupt = tmp_path / "corrupt.sage.tar.gz"
    corrupt.write_bytes(b"\x1f\x8bnot really gzip")
    code, _out, err = _cli(["scan", str(corrupt)], capsys)
    assert code == 2 and "cannot read pack" in err


def test_clean_recording_has_no_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    rec = SageRecorder(title="clean", trace_id="clean-trace", journal_dir=tmp_path / "j", blob_store=tmp_path / "b")
    with rec:
        with rec.llm_call(
            "model",
            inputs={"messages": [{"role": "user", "content": "Where is order 42?"}]},
            data={"model": "gpt-4o-mini-2024-07-18", "usage": {"input_tokens": 3, "input_tokens_details": {"cached_tokens": 0}}},
        ) as llm:
            llm.set_output(text="It shipped. " * 300)
        try:
            guards = {k: v for k, v in corpus.FALSE_POSITIVE_GUARDS.items() if k != "blob_ref"}
            with rec.tool_call("lookup", inputs={"order": 42, "attributes": guards}):
                raise RuntimeError("upstream timeout")
        except RuntimeError:
            pass
    bundle = rec.export(tmp_path / "clean.sage.json")
    pack = pack_artifact(tmp_path / "j", tmp_path / "clean.sage.tar.gz", hmac_key=b"k" * 32)
    for target in (bundle, tmp_path / "j", pack):
        report = scan_path(target)
        assert report.ok, [f.to_dict() for f in report.findings]
    code, out, _err = _cli(["scan", str(pack)], capsys)
    assert code == 0 and "no possible leaks" in out


def test_signed_pack_signature_and_public_key_are_not_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    signing = pytest.importorskip("sage.signing")
    if not signing.signing_available():
        pytest.skip("cryptography not installed")
    monkeypatch.chdir(tmp_path)
    rec = SageRecorder(title="signed", trace_id="signed-trace", blob_store=tmp_path / "b")
    with rec:
        with rec.tool_call("lookup", inputs={"id": 1}) as tool:
            tool.set_output(rows=["x" * 2000])
    bundle = rec.export(tmp_path / "s.sage.json")
    kp = signing.generate_keypair()
    pack = pack_artifact(bundle, tmp_path / "s.sage.tar.gz", hmac_key="k", sign=True, private_key=kp["private_key"])
    report = scan_path(pack)
    assert report.ok, [f.to_dict() for f in report.findings]


def test_pack_json_and_legacy_blob_store_path_are_checked(tmp_path: Path) -> None:
    artifact = tmp_path / "unpacked" / "sage_artifact"
    (artifact / "journal").mkdir(parents=True)
    (artifact / "pack.json").write_text(
        json.dumps({"format": "sage.pack.v2", "note": f"built by {corpus.EMAIL}"}), encoding="utf-8"
    )
    (artifact / "journal" / "manifest.sage.json").write_text(
        json.dumps({"metadata": {"blob_store": corpus.LOCAL_PATH_POSIX, "trace_id": "t"}}), encoding="utf-8"
    )
    report = scan_path(tmp_path / "unpacked")
    assert report.kind == "unpacked-pack"
    found = {(f.rule, f.member, f.path) for f in report.findings}
    assert ("email", "sage_artifact/pack.json", "$.note") in found
    assert ("local_path", "sage_artifact/journal/manifest.sage.json", "$.metadata.blob_store") in found


def test_unredacted_sensitive_key_is_reported(tmp_path: Path) -> None:
    from sage.schema import IncidentBundle, SageSpan

    span = SageSpan(type="tool", name="t", trace_id="t", end_time="2026-01-01T00:00:01Z",
                    inputs={"password": "hunter2", "llm.token_count.prompt": 3, "token": "[REDACTED]"})
    bundle = finalize_bundle(IncidentBundle(title="t", spans=[span]), redact=False, offload_blobs=False)
    path = tmp_path / "raw.sage.json"
    path.write_text(json.dumps(attach_audit_chain(bundle).to_dict()), encoding="utf-8")
    report = scan_path(path, rules=["sensitive_key"])
    found = {(f.rule, f.path) for f in report.findings}
    # The recorder mirrors inputs into typed data (`data.input`), so both copies are reported.
    assert found == {("sensitive_key", "$.spans[0].inputs.password"), ("sensitive_key", "$.spans[0].data.input.password")}


def test_scan_rules_constant_covers_detectors() -> None:
    from sage.detectors import ALL_DETECTORS

    assert set(ALL_DETECTORS) < set(SCAN_RULES)
    with pytest.raises(ScanSetupError):
        scan_path(ROOT / "does-not-exist.sage.json")


# --- handoff -------------------------------------------------------------------------------------


def _handoff(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "SAGE_PACK_KEY": ""}
    return subprocess.run([sys.executable, "-m", "sage.cli", "handoff", *args],
                          capture_output=True, text=True, env=env, cwd=cwd, timeout=180)


def test_handoff_warns_on_findings_and_still_builds(leaky: tuple[Path, Path, Path], tmp_path: Path) -> None:
    _bundle, journal, _pack = leaky
    kit = tmp_path / "kit"
    result = _handoff([str(journal), "--out-dir", str(kit), "--hmac-key", "k" * 32, "--blob-root", str(tmp_path / "blobs")], tmp_path)
    assert result.returncode == 0, result.stderr
    assert "warning" in result.stderr and "possible leak" in result.stderr and "--fail-on-findings" in result.stderr
    _assert_no_value_text(result.stderr + result.stdout)
    assert (kit / "evidence.sage.tar.gz").exists()


def test_handoff_fail_on_findings_blocks(leaky: tuple[Path, Path, Path], tmp_path: Path) -> None:
    _bundle, journal, _pack = leaky
    kit = tmp_path / "kit-blocked"
    result = _handoff([str(journal), "--out-dir", str(kit), "--hmac-key", "k" * 32,
                       "--blob-root", str(tmp_path / "blobs"), "--fail-on-findings"], tmp_path)
    assert result.returncode == 1
    assert "handoff not built" in result.stderr
    _assert_no_value_text(result.stderr + result.stdout)
    assert not kit.exists()
    assert not list(tmp_path.glob(".kit-blocked.staging-*"))


def test_handoff_library_warning(leaky: tuple[Path, Path, Path], tmp_path: Path) -> None:
    from sage.handoff import HandoffLeakWarning, create_handoff

    _bundle, journal, _pack = leaky
    with pytest.warns(HandoffLeakWarning, match="possible leak"):
        create_handoff(journal, tmp_path / "kit-lib", hmac_key=b"k" * 32, blob_root=tmp_path / "blobs")
