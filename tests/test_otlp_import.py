"""OTLP/JSON and OpenInference import against fixtures captured from the real OpenTelemetry SDK.

Fixtures: tests/fixtures/otlp (see generate_fixtures.py there). No optional packages needed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sage.adapters.otel_tap import OpenTelemetryTap
from sage.audit import verify_audit_chain
from sage.bundle_io import save_bundle
from sage.cli import main as cli_main
from sage.importers.openinference import convert_span, convert_spans, import_openinference
from sage.importers.otlp import import_otlp, load_otlp_file, parse_otlp_bytes
from sage.otel_export import export_bundle_to_otel
from sage.verify import verify_artifact

FIXTURES = Path(__file__).parent / "fixtures" / "otlp"
FAKE_KEY = "sk-fixtureFAKEkey0123456789"


@pytest.fixture(autouse=True)
def _blob_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)


def _by_name(bundle):
    return {s.name: s for s in bundle.spans}


@pytest.mark.parametrize("fixture", ["openinference.otlp.json", "openinference.collector.jsonl"])
def test_openinference_fixture_maps_types_parents_and_data(fixture, tmp_path):
    bundle = load_otlp_file(FIXTURES / fixture)
    spans = _by_name(bundle)
    assert {s.type for s in bundle.spans} == {"agent", "retrieval", "llm", "tool", "chain"}
    root = spans["support-agent"]
    assert root.parent_id is None and root.type == "agent"
    assert all(s.parent_id == root.span_id for s in bundle.spans if s is not root)
    assert len(root.span_id) == 16 and int(root.span_id, 16)
    assert bundle.metadata["otel_trace_ids"] == [root.attributes["otel.trace_id"]]

    llm = spans["ChatCompletion"]
    assert llm.type == "llm"
    assert llm.data["model"] == "gpt-4o-mini"
    assert llm.data["provider"] == "openai"
    assert llm.data["parameters"] == {"temperature": 0.0, "max_tokens": 256}
    assert llm.data["usage"] == {"prompt_tokens": 120, "completion_tokens": 18, "total_tokens": 138}
    messages = llm.data["input"]["messages"]
    assert [m["role"] for m in messages] == ["system", "user"]
    call = llm.data["output"]["messages"][0]["tool_calls"][0]
    assert call["function"]["name"] == "lookup_order"
    assert llm.attributes["otel.span_kind"] == "CLIENT"

    tool = spans["lookup_order"]
    assert tool.data["tool_name"] == "lookup_order"
    assert tool.data["input"] == {"order_id": "42"}
    assert tool.data["output"] == "order 42: shipped"
    assert tool.data["tool_call_id"] == "call_1"
    assert tool.data["success"] is True

    retrieval = spans["kb-search"]
    assert retrieval.data["query"] == "order 42 shipping status"
    assert [d["id"] for d in retrieval.data["documents"]] == ["kb-1", "kb-7"]
    assert retrieval.data["documents"][0]["score"] == pytest.approx(0.91)
    assert retrieval.data["documents"][0]["metadata"] == {"source": "kb"}

    failed = spans["refund"]
    assert failed.status == "error"
    assert failed.error.type == "PermissionError"
    assert failed.error.message == "refunds disabled for order 42"
    assert failed.data["success"] is False

    plain = spans["HTTP GET"]
    assert plain.type == "chain"
    assert plain.attributes["http.response.status_code"] == 200
    assert plain.attributes["otel.span_kind"] == "CLIENT"

    assert bundle.status == "failed"
    assert bundle.source.framework == "opentelemetry"
    assert verify_audit_chain(bundle)
    path = save_bundle(bundle, tmp_path / "imported.sage.json")
    assert verify_artifact(path)["ok"] is True
    assert FAKE_KEY not in path.read_text(encoding="utf-8")


def test_hex_and_base64_fixtures_give_identical_ids_and_timestamps():
    from_b64 = load_otlp_file(FIXTURES / "openinference.otlp.json")
    from_hex = load_otlp_file(FIXTURES / "openinference.collector.jsonl")
    shape = lambda b: sorted((s.span_id, s.parent_id, s.start_time, s.end_time, s.type) for s in b.spans)  # noqa: E731
    assert shape(from_b64) == shape(from_hex)


def test_message_to_dict_values_are_typed():
    raw = json.loads((FIXTURES / "openinference.otlp.json").read_text(encoding="utf-8"))
    spans = {s.name: s for s in convert_spans(raw)}
    # MessageToDict writes int64 as strings; they come back as ints.
    assert spans["ChatCompletion"].data["usage"]["total_tokens"] == 138
    assert spans["support-agent"].start_time.endswith("Z")


def test_pydantic_ai_genai_fixture(tmp_path):
    bundle = load_otlp_file(FIXTURES / "pydantic_ai.otlp.json")
    kinds = [s.type for s in bundle.spans]
    assert kinds.count("llm") == 3 and kinds.count("tool") == 2 and kinds.count("agent") == 1
    agent = next(s for s in bundle.spans if s.type == "agent")
    assert agent.agent_id == "geo" and agent.data["agent_name"] == "geo"
    assert agent.data["output"] == {"name": "a", "population": 0}
    assert all(s.parent_id == agent.span_id for s in bundle.spans if s is not agent)
    chat = next(s for s in bundle.spans if s.type == "llm")
    assert chat.data["model"] == "test"
    assert chat.data["provider"] == "test"
    assert chat.data["input"]["messages"][0]["role"] == "user"
    assert set(chat.data["usage"]) == {"input_tokens", "output_tokens"}
    retried, ok = [s for s in bundle.spans if s.type == "tool"]
    assert retried.status == "error" and retried.error.type == "pydantic_ai.exceptions.ToolRetryError"
    assert retried.data["retry"] == {"cause": "model_retry", "attempt": 1, "max_retries": 1}
    assert ok.status == "ok" and ok.data["tool_name"] == "lookup" and ok.data["input"] == {"q": "a"}
    path = save_bundle(bundle, tmp_path / "pai.sage.json")
    assert verify_artifact(path)["ok"] is True
    assert FAKE_KEY not in path.read_text(encoding="utf-8")


def test_otlp_span_kind_is_not_mistaken_for_span_type():
    for kind in (1, "1", "SPAN_KIND_INTERNAL", "SPAN_KIND_CLIENT", 3):
        span = convert_span({"spanId": "00f067aa0ba902b7", "name": "work", "kind": kind, "attributes": []})
        assert span.type == "chain"
    flat = convert_span({"id": "s1", "name": "t", "kind": "TOOL", "attributes": {}})
    assert flat.type == "tool"


def test_status_forms():
    def status(value):
        return convert_span({"spanId": "00f067aa0ba902b7", "name": "x", "status": value}).status

    assert status({"code": 2, "message": "boom"}) == "error"
    assert status({"code": "STATUS_CODE_ERROR"}) == "error"
    assert status({"status_code": "ERROR", "description": "x"}) == "error"
    assert status({"code": "STATUS_CODE_UNSET"}) == "ok"
    assert status({}) == "ok"
    assert status({"code": 1}) == "ok"


def test_sdk_to_json_shape():
    span = convert_span(
        {
            "name": "chat",
            "context": {"trace_id": "0x" + "ab" * 16, "span_id": "0x00f067aa0ba902b7"},
            "parent_id": "0x1111111111111111",
            "kind": "SpanKind.CLIENT",
            "start_time": "2026-01-01T00:00:00.000001Z",
            "end_time": "2026-01-01T00:00:01.000001Z",
            "status": {"status_code": "UNSET"},
            "attributes": {"gen_ai.operation.name": "chat", "gen_ai.request.model": "m1"},
            "events": [],
        }
    )
    assert span.span_id == "00f067aa0ba902b7" and span.parent_id == "1111111111111111"
    assert span.type == "llm" and span.data["model"] == "m1"
    assert span.attributes["otel.span_kind"] == "CLIENT"


def test_round_trip_export_otel_then_import(tmp_path):
    original = load_otlp_file(FIXTURES / "openinference.otlp.json")
    exported = export_bundle_to_otel(original)
    again = import_otlp(json.dumps(exported).encode("utf-8"))
    assert sorted(s.type for s in again.spans) == sorted(s.type for s in original.spans)


def test_unknown_openinference_kind_becomes_custom():
    span = convert_span({"id": "s1", "name": "x", "attributes": {"openinference.span.kind": "UNKNOWN"}})
    assert span.type == "custom"


def test_parse_otlp_bytes_rejects_empty():
    with pytest.raises(ValueError):
        parse_otlp_bytes(b"  \n")


def _cli(*argv: str) -> int:
    with pytest.raises(SystemExit) as exc:
        cli_main(list(argv))
    return int(exc.value.code or 0)


def test_cli_import_otlp_json(tmp_path, capsys):
    out = tmp_path / "cli.sage.json"
    assert _cli("import", str(FIXTURES / "openinference.collector.jsonl"), "--format", "otlp", "--out", str(out)) == 0
    assert verify_artifact(out)["ok"] is True
    assert _cli("verify", str(out)) == 0


def test_tap_ingests_otlp_payload(tmp_path):
    tap = OpenTelemetryTap(trace_id="otlp-tap", journal_dir=tmp_path / "j")
    raw = json.loads((FIXTURES / "openinference.otlp.json").read_text(encoding="utf-8"))
    with tap:
        assert tap.ingest_payload(raw) == 7
    journal_text = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "j").rglob("*") if p.is_file())
    assert FAKE_KEY not in journal_text


def test_protobuf_without_extra_gives_install_hint():
    import subprocess
    import sys

    script = (
        "import sys\n"
        "sys.modules['opentelemetry.proto.collector.trace.v1.trace_service_pb2'] = None\n"
        "from sage.importers.otlp import import_otlp\n"
        "try:\n"
        "    import_otlp(b'\\x0a\\x00')\n"
        "except ImportError as exc:\n"
        "    print(exc)\n"
    )
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert "sage-incident-bundles[otlp]" in proc.stdout


def test_legacy_openinference_import_still_works():
    bundle = import_openinference(
        {"spans": [{"id": "a", "name": "c", "attributes": {"openinference.span.kind": "LLM", "llm.model_name": "x"}}]}
    )
    assert bundle.spans[0].data["model"] == "x"
