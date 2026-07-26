from __future__ import annotations

import json
from pathlib import Path

from sage.audit import require_verified, verify_audit_chain
from sage.bundle_io import load_bundle, save_bundle
from sage.diff import diff_bundles
from sage.recorder import SageRecorder
from sage.regression import write_regression_test
from sage.replay import apply_heal, pure_recorded_replay


def _record_multi_agent(tmp_path: Path):
    with SageRecorder(
        "e2e_multi_agent",
        framework="custom",
        environment="test",
        metadata={"failure_mode": "stale_retrieval_schema"},
    ) as rec:
        with rec.agent_step(
            "orchestrator",
            agent_id="orchestrator",
            inputs={"goal": "update tier"},
            data={"goal": "update tier", "next_action": "handoff"},
        ):
            with rec.handoff(
                "to_researcher",
                from_agent="orchestrator",
                to_agent="researcher",
                context_passed={"customer_id": "c1"},
            ):
                pass
            with rec.retrieval(
                "fetch",
                agent_id="researcher",
                inputs={"query": "c1"},
            ) as retrieval:
                retrieval.set_output(
                    documents=[{"id": "d1", "schema_version": "v1", "stale": True, "score": 0.9}]
                )
                retrieval.mark_root_cause("stale docs")
            with rec.llm_call(
                "plan",
                agent_id="planner",
                inputs={"prompt": "plan"},
            ) as llm:
                llm.set_model("test-llm")
                llm.set_output(response={"args": {"schema": "v1"}})
                llm.set_usage(total=10)
            with rec.tool_call(
                "update_tier",
                agent_id="executor",
                inputs={"schema": "v1"},
            ) as tool:
                tool.set_output(error="schema v2 required; v1 rejected")
                tool.fail("schema drift")
        rec.mark_failure(retrieval.span.span_id, note="stale retrieval")
    path = rec.export(tmp_path / "bundle.sage.json")
    return path


def test_full_forensics_loop(tmp_path):
    path = _record_multi_agent(tmp_path)
    bundle = load_bundle(path, verify=True, rehydrate=True)
    assert bundle.status == "failed"
    assert any(s.type == "handoff" for s in bundle.spans)
    assert any(s.agent_id == "researcher" for s in bundle.spans)

    # Pure replay reconstructs the failure
    replay = pure_recorded_replay(bundle)
    assert replay.ok
    assert replay.final_status == "failed"
    assert replay.error_message

    # Heal root cause and diff
    root = bundle.root_cause_hint
    assert isinstance(root, str)
    healed = apply_heal(
        bundle,
        span_id=root,
        new_output={
            "documents": [{"id": "d1", "schema_version": "v2", "fresh": True, "score": 0.9}]
        },
        new_data={
            "documents": [{"id": "d1", "schema_version": "v2", "fresh": True, "score": 0.9}],
            "query": "c1",
        },
    )
    report = diff_bundles(bundle, healed)
    assert not report.ok
    assert report.first_divergence_span_id is not None
    assert healed.status == "completed"

    # Round-trip export/import/inspect invariants
    round_path = tmp_path / "round.sage.json"
    save_bundle(bundle, round_path)
    # Round-trip the compact on-disk form (hashes bind to blob refs, not rehydrated payloads).
    compact = load_bundle(path, verify=True, rehydrate=False)
    save_bundle(compact, round_path)
    again = load_bundle(round_path, verify=True, rehydrate=False)
    assert again.audit.bundle_hash == compact.audit.bundle_hash
    assert verify_audit_chain(again)

    # make-test output is readable and focused
    out_dir = tmp_path / "generated"
    bundle_path, test_path = write_regression_test(bundle, out_dir, with_heal=True, heal_span_id=root)
    text = test_path.read_text(encoding="utf-8")
    assert "pure_recorded_replay" in text
    assert "Failure mode" in text
    assert "apply_heal" in text
    assert bundle_path.exists()


def test_partial_finalize_then_complete(tmp_path):
    rec = SageRecorder("partial")
    span = rec.start_span("tool", "step", inputs={"x": 1}, data={"tool_name": "step", "input": {"x": 1}, "output": {}, "success": True})
    partial = rec.finalize(partial=True, redact=True)
    assert partial.status == "partial"
    assert verify_audit_chain(partial)
    rec.end_span(span.span_id, status="ok", outputs={"result": "done"})
    final = rec.finalize(partial=False, redact=True, status="completed")
    assert final.status == "completed"
    assert verify_audit_chain(final)
