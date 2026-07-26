from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

from sage.cli import main
from sage.fault import audit_path, recover_bundle_carcass
from sage.recorder import SageRecorder


def _deep_bundle(tmp_path: Path, n: int = 100):
    blob_root = tmp_path / "blobs"
    with SageRecorder("fault-deep", blob_store=blob_root, register_trace=False) as rec:
        with rec.agent_step("orchestrator", agent_id="orch"):
            for i in range(n):
                agent = f"worker-{i % 7}"
                with rec.chain(f"step-{i}", agent_id=agent):
                    with rec.llm_call(f"llm-{i}") as llm:
                        llm.set_model("fault-llm")
                        llm.set_input(prompt=f"task-{i}")
                        llm.set_output(text=f"out-{i}")
                    with rec.tool_call(f"tool-{i}", inputs={"i": i}, agent_id=agent) as tool:
                        tool.set_output(result=i)
                    if i % 11 == 0:
                        with rec.handoff(
                            f"h-{i}",
                            from_agent="orch",
                            to_agent=agent,
                            context_passed={"i": i},
                        ):
                            pass
    path = rec.export(tmp_path / "deep.sage.json")
    return path


def test_truncated_json_carcass_recovers_last_valid_chain(tmp_path, capsys):
    path = _deep_bundle(tmp_path, n=40)
    raw = path.read_text(encoding="utf-8")
    # sort_keys places "spans" late — cut inside the spans array after real objects exist.
    spans_at = raw.find('"spans"')
    assert spans_at > 0
    # Keep header + a large prefix of the spans array, then tear.
    cut = min(len(raw) - 50, spans_at + max(8000, (len(raw) - spans_at) // 2))
    carcass = tmp_path / "carcass.sage.json"
    carcass.write_text(raw[:cut], encoding="utf-8")

    report = recover_bundle_carcass(carcass)
    assert report.ok is False
    assert report.boundary is not None
    assert report.boundary.truncated is True
    assert report.boundary.recovered_span_count >= 1
    assert report.boundary.last_valid_hash
    assert report.boundary.last_valid_hash != ""
    assert report.boundary.failure_anchor["kind"] == "crash_boundary"
    assert report.boundary.rejected_tail_bytes > 0
    assert report.bundle is not None
    assert report.bundle.metadata.get("fault_recovery") is True

    audit = audit_path(carcass)
    assert audit.ok is False
    assert audit.boundary is not None
    assert audit.boundary.last_valid_chain_index >= 0


def test_inspect_and_audit_cli_fail_closed_without_traceback(tmp_path, capsys):
    path = _deep_bundle(tmp_path, n=20)
    raw = path.read_bytes()
    carcass = tmp_path / "killed.sage.json"
    # Simulate SIGKILL after a partial unbuffered write.
    carcass.write_bytes(raw[: max(200, len(raw) // 3)])

    try:
        main(["inspect", str(carcass)])
    except SystemExit as exc:
        assert exc.code == 2
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["ok"] is False
    assert payload["mode"] == "fault_recovery"
    assert payload["boundary"]["failure_anchor"]["kind"] == "crash_boundary"
    assert "Traceback" not in out

    try:
        main(["audit", str(carcass)])
    except SystemExit as exc:
        assert exc.code == 2
    audit_out = json.loads(capsys.readouterr().out)
    assert audit_out["ok"] is False
    assert audit_out["boundary"]["last_valid_hash"]


def test_disk_full_during_atomic_save_does_not_corrupt_prior(tmp_path):
    path = _deep_bundle(tmp_path, n=10)
    original = path.read_text(encoding="utf-8")
    from sage.bundle_io import load_bundle, save_bundle

    bundle = load_bundle(path, verify=True, rehydrate=False)

    real_fsync = None

    def boom_fsync(fd):
        raise OSError(28, "No space left on device")

    with mock.patch("os.fsync", side_effect=boom_fsync):
        try:
            save_bundle(bundle, tmp_path / "new.sage.json", atomic=True)
            raised = False
        except OSError:
            raised = True
    assert raised
    # Prior artifact untouched.
    assert path.read_text(encoding="utf-8") == original
    assert load_bundle(path, verify=True, rehydrate=False).audit.bundle_hash


def test_hijacked_write_truncation_mid_span_array(tmp_path):
    path = _deep_bundle(tmp_path, n=30)
    text = path.read_text(encoding="utf-8")
    # Cut inside the spans array after a few complete objects.
    idx = text.find('"spans"')
    # Find the end of the 3rd span-ish object by cutting after a safe marker.
    marker = '"name": "llm-2"'
    cut_at = text.find(marker)
    assert cut_at > 0
    # Leave an open object / torn tail after the marker.
    torn = text[: cut_at + len(marker)] + ', "inputs": {"prompt": "partial"'
    carcass = tmp_path / "torn.sage.json"
    carcass.write_text(torn, encoding="utf-8")

    report = recover_bundle_carcass(carcass)
    assert report.ok is False
    assert report.boundary is not None
    # Must not raise; must anchor a hash for the uncorrupted prefix spans.
    assert report.boundary.failure_anchor["kind"] == "crash_boundary"
    if report.bundle is not None:
        assert all(s.span_id for s in report.bundle.spans)
