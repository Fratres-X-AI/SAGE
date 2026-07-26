from __future__ import annotations

from sage.adapters.otel_tap import OpenTelemetryTap, attach_otel_tap
from sage.audit import verify_audit_chain
from sage.importers.openinference import convert_span


def test_otel_tap_ingests_openinference_payload(tmp_path):
    tap = OpenTelemetryTap(trace_id="otel-tap-1", journal_dir=tmp_path / "j")
    payload = {
        "spans": [
            {
                "id": "s1",
                "name": "Chat",
                "attributes": {
                    "openinference.span.kind": "LLM",
                    "llm.input_messages": [{"role": "user", "content": "hi"}],
                    "llm.output_messages": [{"role": "assistant", "content": "yo"}],
                },
            }
        ]
    }
    with tap:
        assert tap.ingest_payload(payload) == 1
        cb = tap.as_span_callback()
        assert callable(cb)
    path = tap.export(tmp_path / "tap.sage.json")
    assert path.exists()
    assert verify_audit_chain(tap.recorder.finalized_bundle())


def test_convert_span_public_and_attach_factory():
    span = convert_span(
        {
            "id": "x1",
            "name": "Tool",
            "attributes": {"openinference.span.kind": "TOOL", "input.value": "a"},
        }
    )
    assert span.type == "tool"
    tap = attach_otel_tap(trace_id="factory-1")
    assert tap.recorder.bundle.bundle_id == "factory-1"
