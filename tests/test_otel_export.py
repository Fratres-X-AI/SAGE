from __future__ import annotations

from sage.otel_export import export_bundle_to_otel
from sage.recorder import SageRecorder


def test_otel_export_has_resource_spans(tmp_path):
    with SageRecorder("otel", framework="langchain") as rec:
        with rec.llm_call("chat") as span:
            span.set_model("gpt-test")
            span.set_input(messages=[{"role": "user", "content": "hi"}])
            span.set_output(content="hello")
            span.set_usage(input_tokens=3, output_tokens=1)
    path = rec.export(tmp_path / "b.sage.json")
    from sage.bundle_io import load_bundle

    bundle = load_bundle(path, verify=True, rehydrate=True)
    payload = export_bundle_to_otel(bundle, service_name="sage-test")
    assert "resourceSpans" in payload
    spans = payload["resourceSpans"][0]["scopeSpans"][0]["spans"]
    assert len(spans) == 1
    keys = {a["key"] for a in spans[0]["attributes"]}
    assert "openinference.span.kind" in keys
    assert "gen_ai.request.model" in keys
