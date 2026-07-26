from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from sage.audit import finalize_bundle, require_verified, verify_audit_chain
from sage.bundle_io import load_bundle, save_bundle
from sage.diff import diff_bundles
from sage.inspect_views import build_inspect_report, detect_handoff_cycles
from sage.recorder import SageRecorder
from sage.regression import write_heal_boundary_test
from sage.replay import apply_heal, pure_recorded_replay
from sage.schema import IncidentBundle


ROOT = Path(__file__).resolve().parents[1]


def _record_simple(tmp_path: Path) -> Path:
    with SageRecorder("stress_base", metadata={"failure_mode": "tool_boom"}) as rec:
        with rec.agent_step("boss", agent_id="boss", inputs={"goal": "x"}, data={"goal": "x"}):
            with rec.tool_call("boom", inputs={"v": 1}) as tool:
                tool.set_output(error="boom")
                tool.fail("boom")
        rec.mark_failure(tool.span.span_id, note="boom")
    return rec.export(tmp_path / "base.sage.json")


def test_corrupted_bundle_hash_fail_closed(tmp_path):
    path = _record_simple(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    original = data["audit"]["bundle_hash"]
    data["audit"]["bundle_hash"] = ("0" if original[0] != "0" else "1") + original[1:]
    corrupt = tmp_path / "corrupt_hash.sage.json"
    corrupt.write_text(json.dumps(data), encoding="utf-8")

    bundle = load_bundle(corrupt)
    assert verify_audit_chain(bundle) is False
    try:
        require_verified(bundle)
        assert False, "expected require_verified to raise"
    except ValueError as exc:
        assert "audit" in str(exc).lower() or "bundle_hash" in str(exc).lower()

    proc = subprocess.run(
        [sys.executable, "-m", "sage.cli", "inspect", str(corrupt)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "audit" in proc.stderr.lower() or "bundle_hash" in proc.stderr.lower() or "verification failed" in proc.stderr.lower()

    proc2 = subprocess.run(
        [sys.executable, "-m", "sage.cli", "replay", str(corrupt)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc2.returncode != 0


def test_corrupted_parent_id_fail_closed(tmp_path):
    path = _record_simple(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    # Tamper with a child parent_id after hashing — integrity must fail closed.
    child = next(s for s in data["spans"] if s.get("parent_id"))
    child["parent_id"] = "span_does_not_exist"
    corrupt = tmp_path / "corrupt_parent.sage.json"
    corrupt.write_text(json.dumps(data), encoding="utf-8")

    bundle = load_bundle(corrupt)
    try:
        require_verified(bundle)
        assert False, "expected parent integrity failure"
    except ValueError as exc:
        assert "parent_id" in str(exc)

    proc = subprocess.run(
        [sys.executable, "-m", "sage.cli", "inspect", str(corrupt)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "parent_id" in proc.stderr


def test_redaction_partial_finalize_never_leaks_secret(tmp_path):
    secret = "sk-live-SUPER-SECRET-KEY-999"
    huge = ("PAYLOAD-" * 5000) + secret + ("-TAIL-" * 5000)
    rec = SageRecorder("redaction_race", redaction_policy={"key_fragments": ["api_key", "secret", "token", "sk-live"]})
    span = rec.start_span(
        "tool",
        "dump",
        inputs={"api_key": secret, "blob": huge},
        data={
            "tool_name": "dump",
            "input": {"api_key": secret, "blob": huge},
            "output": {},
            "success": True,
            "side_effects": False,
        },
    )
    # Streaming/partial finalize mid-flight
    partial = rec.finalize(partial=True, redact=True, status="partial")
    dumped = json.dumps(partial.to_dict())
    assert secret not in dumped
    assert "[REDACTED]" in dumped or "api_key" in dumped
    assert verify_audit_chain(partial)

    # Completing must keep redact→hash invariant
    rec.end_span(
        span.span_id,
        status="ok",
        outputs={"result": "ok", "echo_secret": secret, "token": secret},
        data={
            "tool_name": "dump",
            "input": {"api_key": secret, "blob": huge},
            "output": {"result": "ok", "echo_secret": secret, "token": secret},
            "success": True,
            "side_effects": False,
        },
    )
    final = rec.finalize(partial=False, redact=True, status="completed")
    final_dump = json.dumps(final.to_dict())
    assert secret not in final_dump
    assert verify_audit_chain(final)
    # Hash payload itself must not reintroduce plaintext secret via audit records
    assert secret not in json.dumps(final.audit.to_dict())


def test_cyclic_agent_swimlane_reports_cycles_without_exploding():
    with SageRecorder("cyclic", metadata={"failure_mode": "cyclic_handoff"}) as rec:
        with rec.agent_step("a", agent_id="agent_a", inputs={"goal": "loop"}, data={"goal": "loop"}):
            for i in range(5):
                with rec.handoff(f"a2b{i}", from_agent="agent_a", to_agent="agent_b", context_passed={"i": i}):
                    pass
                with rec.handoff(f"b2a{i}", from_agent="agent_b", to_agent="agent_a", context_passed={"i": i}):
                    pass
            with rec.tool_call("stop", agent_id="agent_a", inputs={"x": 1}) as tool:
                tool.fail("cycle budget")
        rec.mark_failure(tool.span.span_id, note="cycle")
    bundle = rec.finalized_bundle()
    cycles = detect_handoff_cycles(bundle)
    assert cycles
    assert any(c[0] == c[-1] for c in cycles)
    report = build_inspect_report(bundle, view="all")
    assert report["ok"] is True
    assert report["swimlane"]["cycle_count"] >= 1
    assert report["swimlane"]["truncated"] is False or report["swimlane"]["event_count"] <= report["swimlane"]["max_events"]
    # Depth/memory safety: cycle detection stays bounded
    assert len(report["swimlane"]["cycles"]) <= 32


def test_with_heal_secondary_divergence_linked_trace(tmp_path):
    with SageRecorder("heal_boundary", metadata={"failure_mode": "stale_then_contract_break"}) as rec:
        with rec.agent_step("orch", agent_id="orch", inputs={"goal": "update"}, data={"goal": "update"}):
            with rec.retrieval("fetch", agent_id="researcher", inputs={"query": "cust"}) as retrieval:
                retrieval.set_output(
                    documents=[{"id": "d1", "schema_version": "v1", "stale": True, "contract": "legacy"}]
                )
                retrieval.mark_root_cause("stale v1")
            with rec.tool_call("update_tier", agent_id="executor", inputs={"schema": "v1"}) as tool:
                tool.set_output(error="schema v2 required; v1 rejected")
                tool.fail("schema drift")
        rec.mark_failure(retrieval.span.span_id, note="stale")
    original = rec.finalized_bundle()
    assert original.status == "failed"

    # Heal retrieval to v2 (fixes original) but mutate tool into a new contract failure.
    secondary = apply_heal(
        original,
        span_id=retrieval.span.span_id,
        new_output={
            "documents": [{"id": "d1", "schema_version": "v2", "fresh": True, "contract": "v2-only"}]
        },
        new_data={
            "query": "cust",
            "documents": [{"id": "d1", "schema_version": "v2", "fresh": True, "contract": "v2-only"}],
        },
        cascade=True,
        secondary_mutations=[
            {
                "span_id": tool.span.span_id,
                "status": "error",
                "error": {"type": "ContractError", "message": "missing v2 field account_tier"},
                "outputs": {"error": "missing v2 field account_tier"},
                "data": {
                    "tool_name": "update_tier",
                    "input": {"schema": "v2"},
                    "output": {"error": "missing v2 field account_tier"},
                    "success": False,
                    "side_effects": False,
                },
            }
        ],
    )
    assert secondary.status == "failed"
    assert secondary.metadata.get("healed_from_bundle_id") == original.bundle_id
    assert secondary.metadata.get("secondary_failure") is True
    report = diff_bundles(original, secondary)
    assert not report.ok
    assert report.first_divergence_span_id is not None

    out_dir = tmp_path / "gen"
    _, test_path = write_heal_boundary_test(
        original,
        secondary,
        out_dir,
        heal_span_id=retrieval.span.span_id,
        test_name="test_heal_boundary",
    )
    text = test_path.read_text(encoding="utf-8")
    assert "secondary_failure" in text
    assert "healed_from_bundle_id" in text
    assert "diff_bundles" in text
    # Execute generated test
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", str(test_path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        env={**dict(**{k: v for k, v in __import__("os").environ.items()}), "PYTHONPATH": str(ROOT / "src")},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
