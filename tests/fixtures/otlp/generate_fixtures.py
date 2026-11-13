"""Regenerate the OTLP fixtures in this directory from real OpenTelemetry SDK runs.

Not run by the test suite. Needs (exact versions used for the committed files)::

    pip install opentelemetry-sdk==1.45.2 opentelemetry-proto==1.45.2 \
        opentelemetry-exporter-otlp-proto-common==1.45.2 pydantic-ai-slim==2.68.0

    python tests/fixtures/otlp/generate_fixtures.py

Outputs:

- ``openinference.otlp.json``: an ``ExportTraceServiceRequest`` encoded by the OTLP exporter's
  own encoder and serialized with ``google.protobuf.json_format.MessageToDict`` (camelCase keys,
  base64 trace/span ids, enum names, int64 values as strings).
- ``openinference.collector.jsonl``: the same spans in OTLP/JSON as the spec and the Collector
  file exporter write them (hex ids, integer enums), split into one request per line.
- ``openinference.otlp.pb``: the same request as binary protobuf.
- ``pydantic_ai.otlp.json``: a real PydanticAI ``TestModel`` run (tool retry, then structured
  output), ``MessageToDict`` form.

Exception stack traces are cut to their last line so no local paths are committed.
"""

from __future__ import annotations

import base64
import json
import random
from pathlib import Path

from google.protobuf.json_format import MessageToDict, ParseDict
from opentelemetry.exporter.otlp.proto.common.trace_encoder import encode_spans
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.sdk.trace.id_generator import IdGenerator
from opentelemetry.trace import SpanKind, Status, StatusCode

HERE = Path(__file__).resolve().parent
FAKE_KEY = "sk-fixtureFAKEkey0123456789"


class SeededIds(IdGenerator):
    def __init__(self, seed: int) -> None:
        self._rng = random.Random(seed)

    def generate_span_id(self) -> int:
        return self._rng.getrandbits(64) or 1

    def generate_trace_id(self) -> int:
        return self._rng.getrandbits(128) or 1


def _provider(seed: int, service: str) -> tuple[TracerProvider, InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider(resource=Resource.create({"service.name": service}), id_generator=SeededIds(seed))
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider, exporter


def _openinference_spans():
    provider, exporter = _provider(7, "support-bot")
    tracer = provider.get_tracer("fixture.openinference", "1.0.0")
    with tracer.start_as_current_span("support-agent") as agent:
        agent.set_attribute("openinference.span.kind", "AGENT")
        agent.set_attribute("input.value", "Where is order 42?")
        agent.set_attribute("input.mime_type", "text/plain")
        with tracer.start_as_current_span("kb-search") as ret:
            ret.set_attribute("openinference.span.kind", "RETRIEVER")
            ret.set_attribute("input.value", "order 42 shipping status")
            for i, (doc_id, content, score) in enumerate(
                [("kb-1", "Orders ship within 2 days.", 0.91), ("kb-7", "Refunds take 5 days.", 0.42)]
            ):
                ret.set_attribute(f"retrieval.documents.{i}.document.id", doc_id)
                ret.set_attribute(f"retrieval.documents.{i}.document.content", content)
                ret.set_attribute(f"retrieval.documents.{i}.document.score", score)
                ret.set_attribute(f"retrieval.documents.{i}.document.metadata", json.dumps({"source": "kb"}))
        with tracer.start_as_current_span("ChatCompletion", kind=SpanKind.CLIENT) as llm:
            llm.set_attribute("openinference.span.kind", "LLM")
            llm.set_attribute("llm.model_name", "gpt-4o-mini")
            llm.set_attribute("llm.provider", "openai")
            llm.set_attribute("llm.system", "openai")
            llm.set_attribute("llm.invocation_parameters", json.dumps({"temperature": 0.0, "max_tokens": 256}))
            llm.set_attribute("llm.input_messages.0.message.role", "system")
            llm.set_attribute("llm.input_messages.0.message.content", "You are a support agent.")
            llm.set_attribute("llm.input_messages.1.message.role", "user")
            llm.set_attribute("llm.input_messages.1.message.content", f"Where is order 42? my key is {FAKE_KEY}")
            llm.set_attribute("llm.output_messages.0.message.role", "assistant")
            llm.set_attribute("llm.output_messages.0.message.tool_calls.0.tool_call.id", "call_1")
            llm.set_attribute("llm.output_messages.0.message.tool_calls.0.tool_call.function.name", "lookup_order")
            llm.set_attribute(
                "llm.output_messages.0.message.tool_calls.0.tool_call.function.arguments", '{"order_id": "42"}'
            )
            llm.set_attribute("llm.token_count.prompt", 120)
            llm.set_attribute("llm.token_count.completion", 18)
            llm.set_attribute("llm.token_count.total", 138)
            llm.set_attribute("input.value", "Where is order 42?")
            llm.set_attribute("output.value", '{"tool_calls": 1}')
            llm.set_attribute("output.mime_type", "application/json")
        with tracer.start_as_current_span("lookup_order") as tool:
            tool.set_attribute("openinference.span.kind", "TOOL")
            tool.set_attribute("tool.name", "lookup_order")
            tool.set_attribute("tool.description", "Look up an order by id.")
            tool.set_attribute("tool.parameters", json.dumps({"type": "object", "properties": {"order_id": {}}}))
            tool.set_attribute("tool_call.id", "call_1")
            tool.set_attribute("input.value", '{"order_id": "42"}')
            tool.set_attribute("input.mime_type", "application/json")
            tool.set_attribute("output.value", "order 42: shipped")
        with tracer.start_as_current_span("refund") as bad:
            bad.set_attribute("openinference.span.kind", "TOOL")
            bad.set_attribute("tool.name", "refund")
            bad.set_attribute("input.value", '{"order_id": "42"}')
            try:
                raise PermissionError("refunds disabled for order 42")
            except PermissionError as exc:
                bad.record_exception(exc)
                bad.set_status(Status(StatusCode.ERROR, "refunds disabled for order 42"))
        with tracer.start_as_current_span("HTTP GET", kind=SpanKind.CLIENT) as http:
            http.set_attribute("http.request.method", "GET")
            http.set_attribute("url.full", "https://orders.internal.example/42")
            http.set_attribute("http.response.status_code", 200)
        with tracer.start_as_current_span("format-answer") as chain:
            chain.set_attribute("openinference.span.kind", "CHAIN")
            chain.set_attribute("input.value", "order 42: shipped")
            chain.set_attribute("output.value", "Your order shipped.")
        agent.set_attribute("output.value", "Your order shipped.")
        agent.set_status(Status(StatusCode.OK))
    return exporter.get_finished_spans()


def _pydantic_ai_spans():
    from pydantic import BaseModel
    from pydantic_ai import Agent, ModelRetry
    from pydantic_ai.models.instrumented import InstrumentationSettings
    from pydantic_ai.models.test import TestModel

    provider, exporter = _provider(11, "pydantic-ai-fixture")

    class City(BaseModel):
        name: str
        population: int

    agent = Agent(TestModel(), output_type=City, name="geo")
    agent.instrument = InstrumentationSettings(tracer_provider=provider)
    calls = {"n": 0}

    @agent.tool_plain
    def lookup(q: str) -> str:
        """Look up a city."""
        calls["n"] += 1
        if calls["n"] == 1:
            raise ModelRetry("backend busy, retry")
        return f"city {q}"

    agent.run_sync(f"Find a city. key={FAKE_KEY}")
    return exporter.get_finished_spans()


def _trim_stacktraces(node):
    if isinstance(node, dict):
        if node.get("key") == "exception.stacktrace" and isinstance(node.get("value"), dict):
            text = node["value"].get("stringValue", "")
            node["value"]["stringValue"] = text.strip().splitlines()[-1] if text.strip() else ""
        for value in node.values():
            _trim_stacktraces(value)
    elif isinstance(node, list):
        for value in node:
            _trim_stacktraces(value)


def _request_dict(spans) -> dict:
    as_dict = MessageToDict(encode_spans(spans))
    _trim_stacktraces(as_dict)
    return as_dict


def _b64_to_hex(node):
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            if key in {"traceId", "spanId", "parentSpanId"} and isinstance(value, str):
                out[key] = base64.b64decode(value).hex()
            else:
                out[key] = _b64_to_hex(value)
        return out
    if isinstance(node, list):
        return [_b64_to_hex(v) for v in node]
    return node


def main() -> None:
    oi = _request_dict(_openinference_spans())
    (HERE / "openinference.otlp.json").write_text(json.dumps(oi, indent=1) + "\n", encoding="utf-8")

    message = ParseDict(oi, ExportTraceServiceRequest())
    (HERE / "openinference.otlp.pb").write_bytes(message.SerializeToString(deterministic=True))

    spec_json = _b64_to_hex(MessageToDict(message, use_integers_for_enums=True))
    spans = spec_json["resourceSpans"][0]["scopeSpans"][0]["spans"]
    half = len(spans) // 2
    lines = []
    for chunk in (spans[:half], spans[half:]):
        req = json.loads(json.dumps(spec_json))
        req["resourceSpans"][0]["scopeSpans"][0]["spans"] = chunk
        lines.append(json.dumps(req, separators=(",", ":")))
    (HERE / "openinference.collector.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")

    pai = _request_dict(_pydantic_ai_spans())
    (HERE / "pydantic_ai.otlp.json").write_text(json.dumps(pai, indent=1) + "\n", encoding="utf-8")
    print("wrote fixtures to", HERE)


if __name__ == "__main__":
    main()
