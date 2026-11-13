"""OTLP protobuf import, and live spans from the real OpenTelemetry SDK (pinned in the ``otlp`` extra).

Needs: opentelemetry-proto, opentelemetry-sdk, opentelemetry-exporter-otlp-proto-common
(see constraints/otel-agents.txt). Skipped when they are missing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("opentelemetry.proto.collector.trace.v1.trace_service_pb2")
pytest.importorskip("opentelemetry.sdk.trace")
pytest.importorskip("opentelemetry.exporter.otlp.proto.common.trace_encoder")

from google.protobuf.json_format import MessageToDict
from opentelemetry.exporter.otlp.proto.common.trace_encoder import encode_spans
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import Status, StatusCode

from sage.bundle_io import save_bundle
from sage.cli import main as cli_main
from sage.importers.otlp import import_otlp, load_otlp_file, otlp_protobuf_to_dict
from sage.verify import verify_artifact

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "otlp"
SECRET = "sk-liveSECRET0123456789abcdef"


@pytest.fixture(autouse=True)
def _blob_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)


def _shape(bundle):
    return sorted((s.span_id, s.parent_id, s.type, s.status, s.name) for s in bundle.spans)


def test_protobuf_fixture_matches_json_fixture(tmp_path):
    from_pb = load_otlp_file(FIXTURES / "openinference.otlp.pb")
    from_json = load_otlp_file(FIXTURES / "openinference.otlp.json")
    assert _shape(from_pb) == _shape(from_json)
    llm = next(s for s in from_pb.spans if s.type == "llm")
    assert llm.data["usage"]["total_tokens"] == 138
    path = save_bundle(from_pb, tmp_path / "pb.sage.json")
    assert verify_artifact(path)["ok"] is True


def _live_spans():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("sage.test")
    with tracer.start_as_current_span("invoke_agent planner") as agent:
        agent.set_attribute("gen_ai.operation.name", "invoke_agent")
        agent.set_attribute("gen_ai.agent.name", "planner")
        with tracer.start_as_current_span("chat m1") as chat:
            chat.set_attribute("gen_ai.operation.name", "chat")
            chat.set_attribute("gen_ai.request.model", "m1")
            chat.set_attribute("gen_ai.request.temperature", 0.2)
            chat.set_attribute("gen_ai.usage.input_tokens", 11)
            chat.set_attribute("gen_ai.usage.output_tokens", 3)
            chat.set_attribute(
                "gen_ai.input.messages", f'[{{"role":"user","parts":[{{"type":"text","content":"key {SECRET}"}}]}}]'
            )
            chat.set_attribute("gen_ai.response.finish_reasons", ("stop",))
        with tracer.start_as_current_span("execute_tool search") as tool:
            tool.set_attribute("gen_ai.operation.name", "execute_tool")
            tool.set_attribute("gen_ai.tool.name", "search")
            tool.set_attribute("gen_ai.tool.call.arguments", '{"q": "x"}')
            try:
                raise TimeoutError("search backend timed out")
            except TimeoutError as exc:
                tool.record_exception(exc)
                tool.set_status(Status(StatusCode.ERROR, str(exc)))
    return exporter.get_finished_spans()


def test_live_sdk_spans_via_protobuf_bytes(tmp_path):
    raw = encode_spans(_live_spans()).SerializeToString()
    bundle = import_otlp(raw, title="live")
    by_type = {s.type: s for s in bundle.spans}
    assert set(by_type) == {"agent", "llm", "tool"}
    assert by_type["agent"].agent_id == "planner"
    assert by_type["llm"].parent_id == by_type["agent"].span_id
    assert by_type["tool"].parent_id == by_type["agent"].span_id
    assert by_type["llm"].data["model"] == "m1"
    assert by_type["llm"].data["parameters"] == {"temperature": 0.2}
    assert by_type["llm"].data["usage"] == {"input_tokens": 11, "output_tokens": 3}
    assert by_type["llm"].data["finish_reason"] == ["stop"]
    assert by_type["tool"].status == "error"
    assert by_type["tool"].error.type == "TimeoutError"
    assert "Users" not in (by_type["tool"].error.stack or "")
    path = save_bundle(bundle, tmp_path / "live.sage.json")
    assert verify_artifact(path)["ok"] is True
    assert SECRET not in path.read_text(encoding="utf-8")


def test_live_sdk_spans_via_message_to_dict():
    request = encode_spans(_live_spans())
    as_dict = MessageToDict(request)
    assert as_dict["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["kind"].startswith("SPAN_KIND_")
    from_dict = import_otlp(as_dict)
    from_bytes = import_otlp(request.SerializeToString())
    assert _shape(from_dict) == _shape(from_bytes)


def test_cli_import_protobuf(tmp_path):
    src = tmp_path / "traces.pb"
    src.write_bytes(encode_spans(_live_spans()).SerializeToString())
    out = tmp_path / "out.sage.json"
    with pytest.raises(SystemExit) as exc:
        cli_main(["import", str(src), "--format", "otlp", "--out", str(out)])
    assert exc.value.code == 0
    assert verify_artifact(out)["ok"] is True


def test_corrupt_protobuf_is_rejected():
    with pytest.raises(ValueError):
        otlp_protobuf_to_dict(b"\x0a\xff\xff\xff\xff\x0f garbage")
