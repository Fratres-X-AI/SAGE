from __future__ import annotations

import json

from sage.audit import finalize_bundle, redact_bundle, require_verified, verify_audit_chain
from sage.diff import diff_bundles
from sage.importers.openinference import import_openinference
from sage.recorder import SageRecorder
from sage.replay import apply_heal, pure_recorded_replay, replay_bundle
from sage.schema import IncidentBundle, SageSpan, ensure_typed_data


def test_recorder_exports_verified_bundle(tmp_path):
    with SageRecorder("test run") as recorder:
        with recorder.tool_call("search", inputs={"q": "hello"}):
            pass
    path = recorder.export(tmp_path / "incident.sage.json", redact=True)
    bundle = IncidentBundle.from_dict(json.loads(path.read_text(encoding="utf-8")))
    assert bundle.schema_version == "1.0"
    assert len(bundle.spans) == 1
    assert verify_audit_chain(bundle)
    require_verified(bundle)


def test_redaction_masks_sensitive_keys_before_hash():
    bundle = IncidentBundle(title="secret")
    span = SageSpan.from_kind(
        "TOOL",
        "auth",
        trace_id=bundle.bundle_id,
        inputs={"api_key": "sk-test", "query": "ok"},
        outputs={"token": "abc", "result": "ok"},
    )
    span.finish(status="ok")
    bundle.add_span(span)
    for s in bundle.spans:
        s.trace_id = bundle.bundle_id
    redacted = redact_bundle(bundle)
    assert redacted.spans[0].inputs["api_key"] == "[REDACTED]"
    finalized = finalize_bundle(bundle, redact=True)
    assert verify_audit_chain(finalized)


def test_openinference_import_maps_llm_span():
    payload = {
        "spans": [
            {
                "id": "span1",
                "name": "ChatCompletion",
                "attributes": {
                    "openinference.span.kind": "LLM",
                    "llm.input_messages": [{"role": "user", "content": "hi"}],
                    "llm.output_messages": [{"role": "assistant", "content": "hello"}],
                },
            }
        ]
    }
    bundle = import_openinference(payload, title="imported")
    assert bundle.spans[0].type == "llm"
    assert verify_audit_chain(bundle)


def test_replay_detects_output_drift():
    recorded = IncidentBundle(title="recorded")
    span = SageSpan.from_kind(
        "TOOL",
        "update",
        trace_id=recorded.bundle_id,
        inputs={"x": 1},
        outputs={"result": "ok"},
    )
    span.finish(status="ok")
    ensure_typed_data(span)
    recorded.add_span(span)
    recorded = finalize_bundle(recorded, redact=False)
    candidate = SageSpan.from_kind(
        "TOOL",
        "update",
        span_id=span.span_id,
        trace_id=recorded.bundle_id,
        inputs={"x": 1},
        outputs={"result": "bad"},
    )
    candidate.finish(status="ok")
    ensure_typed_data(candidate)
    result = replay_bundle(recorded, [candidate], strict=True)
    assert not result.ok
    assert result.report is not None
    assert result.report.divergent_span_count >= 1


def test_audit_chain_is_deterministic():
    bundle = IncidentBundle(title="t")
    span = SageSpan.from_kind(
        "LLM",
        "call",
        trace_id=bundle.bundle_id,
        inputs={"prompt": "hi"},
        outputs={"text": "hi"},
        attributes={"model": "m"},
    )
    span.finish(status="ok")
    ensure_typed_data(span)
    bundle.add_span(span)
    finalized = finalize_bundle(bundle, redact=False)
    assert finalized.audit.chain[0]["prev_hash"] == "0" * 64
    assert finalized.audit.bundle_hash
