"""Convert OpenTelemetry / OpenInference spans into SAGE spans and sealed bundles.

Accepted span shapes (all may be mixed in one payload):

- OTLP/JSON ``resourceSpans`` as written by the OpenTelemetry Collector file exporter and the
  OTLP spec (hex ``traceId``/``spanId``, integer enums), or as produced by
  ``google.protobuf.json_format.MessageToDict`` on an ``ExportTraceServiceRequest`` (base64 ids,
  ``SPAN_KIND_*`` / ``STATUS_CODE_*`` enum names, int64 values as strings). A list of such
  requests (one per JSON Lines row) is accepted too.
- ``ReadableSpan.to_json()`` dicts from the Python SDK (``context.span_id`` as ``0x…`` hex).
- Flat span dicts with ``id`` / ``spanId`` and a dict of attributes.

Semantic conventions mapped into typed ``span.data``: OpenInference (``openinference.span.kind``,
``input.value``, ``output.value``, ``llm.model_name``, ``llm.invocation_parameters``,
``llm.input_messages.*`` / ``llm.output_messages.*``, ``llm.token_count.*``, ``tool.name``,
``retrieval.documents.*``) and OpenTelemetry GenAI (``gen_ai.operation.name``,
``gen_ai.request.model`` / ``gen_ai.response.model``, ``gen_ai.input.messages`` /
``gen_ai.output.messages``, ``gen_ai.usage.*``, ``gen_ai.tool.*``, ``gen_ai.agent.name``).
The raw attributes are kept on ``span.attributes``. Redaction runs when the bundle is sealed.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from pathlib import Path
from typing import Any

from sage.audit import finalize_bundle
from sage.schema import (
    BundleSource,
    IncidentBundle,
    SageSpan,
    SpanError,
    ensure_typed_data,
    new_id,
    normalize_status,
    normalize_type,
    utc_now,
)

OPENINFERENCE_KIND_MAP = {
    "AGENT": "agent",
    "CHAIN": "chain",
    "EMBEDDING": "embedding",
    "EVALUATOR": "evaluator",
    "GUARDRAIL": "guardrail",
    "LLM": "llm",
    "PROMPT": "prompt",
    "RERANKER": "reranker",
    "RETRIEVER": "retrieval",
    "TOOL": "tool",
    "POLICY": "policy",
    "HANDOFF": "handoff",
}

GEN_AI_OPERATION_MAP = {
    "chat": "llm",
    "text_completion": "llm",
    "create_agent": "agent",
    "embeddings": "embedding",
    "execute_tool": "tool",
    "generate_content": "llm",
    "invoke_agent": "agent",
    "invoke_agent_client": "agent",
    "invoke_agent_internal": "agent",
    "invoke_workflow": "chain",
    "retrieve": "retrieval",
}

OTEL_SPAN_KINDS = {
    0: "UNSPECIFIED",
    1: "INTERNAL",
    2: "SERVER",
    3: "CLIENT",
    4: "PRODUCER",
    5: "CONSUMER",
}

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_ABS_FRAME_PATH = re.compile(r'File "([^"]+)"')
_MAX_STACK = 4000


def load_openinference_file(path: str | Path, *, title: str | None = None) -> IncidentBundle:
    """Load a JSON or JSON Lines OTLP / OpenInference export and seal it as a SAGE bundle."""
    data = load_json_or_jsonl(Path(path).read_text(encoding="utf-8-sig"))
    return import_openinference(data, title=title or Path(path).stem)


def load_json_or_jsonl(text: str) -> Any:
    """Parse one JSON document, or JSON Lines (one document per non-empty line) into a list."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        rows = [line for line in text.splitlines() if line.strip()]
        if len(rows) < 2:
            raise
        return [json.loads(line) for line in rows]


def import_openinference(
    data: Any,
    *,
    title: str = "Imported trace",
    framework: str = "openinference",
    importer: str = "openinference",
) -> IncidentBundle:
    spans = convert_spans(data)
    bundle = IncidentBundle(
        title=title,
        source=BundleSource(framework=framework, run_id=new_id("run"), environment="imported"),
        metadata={"importer": importer},
        status="failed" if any(s.status in {"error", "timeout"} for s in spans) else "completed",
    )
    trace_ids = sorted({str(s.attributes["otel.trace_id"]) for s in spans if s.attributes.get("otel.trace_id")})
    if trace_ids:
        bundle.metadata["otel_trace_ids"] = trace_ids
    for span in spans:
        span.trace_id = bundle.bundle_id
        ensure_typed_data(span)
        bundle.add_span(span)
    return finalize_bundle(bundle, redact=True, status=bundle.status)


def convert_spans(data: Any) -> list[SageSpan]:
    """Convert every span in ``data``; duplicates (same span id) keep the first copy.

    Spans are ordered by start time so parents precede their children.
    """
    seen: set[str] = set()
    converted: list[SageSpan] = []
    for raw in _iter_spans(data):
        span = _convert_span(raw)
        if span.span_id in seen:
            continue
        seen.add(span.span_id)
        converted.append(span)
    order = {s.span_id: i for i, s in enumerate(converted)}
    parents = {s.span_id: s.parent_id for s in converted}

    def depth(span_id: str) -> int:
        level, seen_ids, current = 0, {span_id}, parents.get(span_id)
        while current in parents and current not in seen_ids:
            seen_ids.add(current)
            level += 1
            current = parents[current]
        return level

    converted.sort(key=lambda s: (s.start_time, depth(s.span_id), order[s.span_id]))
    return converted


def _iter_spans(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        spans: list[dict[str, Any]] = []
        for item in data:
            if isinstance(item, dict) and ("resourceSpans" in item or "resource_spans" in item):
                spans.extend(_iter_otel_resource_spans(item))
            elif isinstance(item, dict):
                spans.append(item)
        return spans
    if not isinstance(data, dict):
        raise ValueError("OpenInference import expects a dict or list of spans")
    if "spans" in data and isinstance(data["spans"], list):
        return [span for span in data["spans"] if isinstance(span, dict)]
    if "resourceSpans" in data or "resource_spans" in data:
        return list(_iter_otel_resource_spans(data))
    if "trace" in data:
        return _iter_spans(data["trace"])
    return [data]


def _iter_otel_resource_spans(data: dict[str, Any]) -> list[dict[str, Any]]:
    spans: list[dict[str, Any]] = []
    for resource_span in data.get("resourceSpans") or data.get("resource_spans") or []:
        scopes = (
            resource_span.get("scopeSpans")
            or resource_span.get("scope_spans")
            or resource_span.get("instrumentationLibrarySpans")
            or []
        )
        for scope_span in scopes:
            scope = scope_span.get("scope") or scope_span.get("instrumentationLibrary") or {}
            for span in scope_span.get("spans", []):
                if isinstance(span, dict) and scope.get("name"):
                    span = {**span, "_scope": {"name": scope.get("name"), "version": scope.get("version")}}
                spans.append(span)
    return spans


def convert_span(span: dict[str, Any]) -> SageSpan:
    """Public converter: one OTel / OpenInference span dict → SageSpan."""
    return _convert_span(span)


def _convert_span(span: dict[str, Any]) -> SageSpan:
    attributes = _normalize_attributes(span.get("attributes") or {})
    context = span.get("context") if isinstance(span.get("context"), dict) else {}
    span_type = _detect_type(span, attributes)
    status = _detect_status(span)
    events = _convert_events(span.get("events"))
    inputs, outputs = _split_io(attributes)

    trace_id = _normalize_id(span.get("traceId") or span.get("trace_id") or context.get("trace_id"), 16)
    if trace_id:
        attributes.setdefault("otel.trace_id", trace_id)
    otel_kind = _otel_kind(span.get("kind"))
    if otel_kind:
        attributes.setdefault("otel.span_kind", otel_kind)
    scope = span.get("_scope")
    if isinstance(scope, dict) and scope.get("name"):
        attributes.setdefault("otel.scope.name", scope["name"])
        if scope.get("version"):
            attributes.setdefault("otel.scope.version", scope["version"])

    span_id = _normalize_id(span.get("spanId") or span.get("span_id") or span.get("id") or context.get("span_id"), 8)
    parent_id = _normalize_id(span.get("parentSpanId") or span.get("parent_span_id") or span.get("parent_id"), 8)
    error = _extract_error(span, attributes, events)
    if status == "ok" and error is not None and _status_code(span) is None and "error.type" in attributes:
        status = "error"
    name = str(span.get("name") or attributes.get("name") or span_type)
    result = SageSpan(
        span_id=span_id or new_id("span"),
        parent_id=parent_id,
        type=span_type,
        name=name,
        start_time=_timestamp(span.get("startTimeUnixNano") or span.get("start_time")) or utc_now(),
        end_time=_timestamp(span.get("endTimeUnixNano") or span.get("end_time")) or utc_now(),
        status=status,
        inputs=inputs,
        outputs=outputs,
        attributes=attributes,
        events=events,
        data=_typed_data(span_type, name, attributes, status),
        error=error if status in {"error", "timeout"} else None,
        agent_id=_optional_str(
            attributes.get("agent_id") or attributes.get("gen_ai.agent.name") or attributes.get("agent.name")
        ),
    )
    ensure_typed_data(result)
    return result


# -- attribute values ------------------------------------------------------------------------------


def _normalize_attributes(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return {str(k): _plain(v) for k, v in raw.items()}
    normalized: dict[str, Any] = {}
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict) or "key" not in item:
                continue
            normalized[str(item["key"])] = _otel_value(item.get("value"))
    return normalized


def _plain(value: Any) -> Any:
    if isinstance(value, tuple):
        return [_plain(v) for v in value]
    return value


def _otel_value(value: Any) -> Any:
    """Decode an OTLP ``AnyValue`` (JSON or ``MessageToDict`` form)."""
    if not isinstance(value, dict):
        return value
    if "stringValue" in value:
        return value["stringValue"]
    if "boolValue" in value:
        return bool(value["boolValue"])
    if "intValue" in value:
        try:
            return int(value["intValue"])
        except (TypeError, ValueError):
            return value["intValue"]
    if "doubleValue" in value:
        try:
            return float(value["doubleValue"])
        except (TypeError, ValueError):
            return value["doubleValue"]
    if "bytesValue" in value:
        return value["bytesValue"]
    if "arrayValue" in value:
        return [_otel_value(item) for item in (value["arrayValue"] or {}).get("values", [])]
    if "kvlistValue" in value:
        return {
            item["key"]: _otel_value(item.get("value"))
            for item in (value["kvlistValue"] or {}).get("values", [])
            if "key" in item
        }
    if not value:
        return None
    return value


def _maybe_json(value: Any) -> Any:
    if isinstance(value, str):
        text = value.strip()
        if text[:1] in {"{", "["}:
            try:
                return json.loads(text)
            except ValueError:
                return value
    return value


def _normalize_id(value: Any, nbytes: int) -> str | None:
    """Return a lowercase hex id. Accepts hex (OTLP/JSON), ``0x`` hex (SDK) or base64 (protobuf JSON)."""
    if value in (None, ""):
        return None
    if isinstance(value, int):
        return None if value == 0 else format(value, f"0{nbytes * 2}x")
    text = str(value)
    if text.lower().startswith("0x"):
        text = text[2:]
    if len(text) == nbytes * 2 and _HEX.match(text):
        return None if set(text) == {"0"} else text.lower()
    if len(text) == 4 * ((nbytes + 2) // 3):
        try:
            decoded = base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError):
            decoded = b""
        if len(decoded) == nbytes:
            return None if not any(decoded) else decoded.hex()
    return str(value)


def _otel_kind(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
        return OTEL_SPAN_KINDS.get(int(value))
    text = str(value).upper()
    for prefix in ("SPAN_KIND_", "SPANKIND."):
        if text.startswith(prefix):
            return text[len(prefix):]
    return text if text in OTEL_SPAN_KINDS.values() else None


# -- type / status / error -------------------------------------------------------------------------


def _detect_type(span: dict[str, Any], attributes: dict[str, Any]) -> Any:
    raw_kind = attributes.get("openinference.span.kind")
    if raw_kind:
        key = str(raw_kind).upper()
        if key in OPENINFERENCE_KIND_MAP:
            return OPENINFERENCE_KIND_MAP[key]
        try:
            return normalize_type(str(raw_kind))
        except ValueError:
            return "custom"
    sage_type = attributes.get("sage.span.type")
    if sage_type:
        try:
            return normalize_type(str(sage_type))
        except ValueError:
            pass
    operation = attributes.get("gen_ai.operation.name")
    if operation:
        mapped = GEN_AI_OPERATION_MAP.get(str(operation))
        if mapped:
            return mapped
    # ``kind`` is the OTel span kind (INTERNAL/CLIENT/...) on OTLP spans; only flat
    # OpenInference-style dicts put a span category there.
    flat_kind = span.get("kind")
    if isinstance(flat_kind, str) and flat_kind.upper() in OPENINFERENCE_KIND_MAP:
        return OPENINFERENCE_KIND_MAP[flat_kind.upper()]
    return "chain"


def _status_code(span: dict[str, Any]) -> str | None:
    status = span.get("status")
    if not isinstance(status, dict):
        return None
    raw = status.get("code", status.get("status_code"))
    if raw in (None, ""):
        return None
    code = str(raw).upper()
    for prefix in ("STATUS_CODE_", "STATUSCODE."):
        if code.startswith(prefix):
            code = code[len(prefix):]
    return {"0": "UNSET", "1": "OK", "2": "ERROR"}.get(code, code)


def _detect_status(span: dict[str, Any]) -> Any:
    status = span.get("status")
    if isinstance(status, dict):
        return "error" if _status_code(span) == "ERROR" else "ok"
    raw = str(status or span.get("statusCode") or "ok")
    try:
        return normalize_status(raw)
    except ValueError:
        return "ok"


def _short_stack(text: str) -> str:
    def repl(match: "re.Match[str]") -> str:
        parts = re.split(r"[\\/]+", match.group(1))
        return f'File "{"/".join(parts[-2:])}"'

    return _ABS_FRAME_PATH.sub(repl, text)[-_MAX_STACK:]


def _convert_events(raw: Any) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for event in raw or []:
        if not isinstance(event, dict):
            continue
        attrs = _normalize_attributes(event.get("attributes") or {})
        if isinstance(attrs.get("exception.stacktrace"), str):
            attrs["exception.stacktrace"] = _short_stack(attrs["exception.stacktrace"])
        out: dict[str, Any] = {
            "name": str(event.get("name") or "event"),
            "timestamp": _timestamp(event.get("timeUnixNano") or event.get("timestamp")) or utc_now(),
        }
        if attrs:
            out["attributes"] = attrs
        events.append(out)
    return events


def _extract_error(
    span: dict[str, Any], attributes: dict[str, Any], events: list[dict[str, Any]]
) -> SpanError | None:
    for event in events:
        if event["name"] == "exception":
            attrs = event.get("attributes") or {}
            return SpanError(
                type=str(attrs.get("exception.type") or attributes.get("error.type") or "Error"),
                message=str(attrs.get("exception.message") or ""),
                stack=attrs.get("exception.stacktrace") or None,
            )
    status = span.get("status")
    message = status.get("message") or status.get("description") if isinstance(status, dict) else None
    if "error.type" in attributes:
        return SpanError(type=str(attributes["error.type"]), message=str(message or attributes["error.type"]))
    if message:
        return SpanError(type="Error", message=str(message))
    return None


# -- typed data ------------------------------------------------------------------------------------


def _split_io(attributes: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    inputs: dict[str, Any] = {}
    outputs: dict[str, Any] = {}
    for key, value in attributes.items():
        lowered = key.lower()
        if ".input" in lowered or lowered.startswith("input") or lowered.endswith(".arguments"):
            inputs[key] = value
        elif ".output" in lowered or lowered.startswith("output") or lowered.endswith(".result"):
            outputs[key] = value
    return inputs, outputs


def _unflatten(attributes: dict[str, Any], prefix: str) -> list[Any] | None:
    """Rebuild OpenInference flattened lists (``prefix.0.message.role``) into nested objects."""
    direct = attributes.get(prefix)
    if isinstance(direct, list):
        return direct
    parsed = _maybe_json(direct)
    if isinstance(parsed, list):
        return parsed
    tree: dict[str, Any] = {}
    marker = prefix + "."
    for key, value in attributes.items():
        if not key.startswith(marker):
            continue
        node = tree
        parts = key[len(marker):].split(".")
        for part in parts[:-1]:
            child = node.get(part)
            if not isinstance(child, dict):
                child = node[part] = {}
            node = child
        node[parts[-1]] = value
    if not tree:
        return None
    result = _listify(tree)
    return result if isinstance(result, list) else [result]


def _listify(node: Any) -> Any:
    if not isinstance(node, dict):
        return node
    if node and all(k.isdigit() for k in node):
        return [_unwrap(_listify(node[k])) for k in sorted(node, key=int)]
    return {k: _listify(v) for k, v in node.items()}


def _unwrap(item: Any) -> Any:
    if isinstance(item, dict) and len(item) == 1:
        (key, value), = item.items()
        if key in {"message", "document", "tool_call", "embedding", "content"} and isinstance(value, dict):
            return value
    return item


def _io_value(attributes: dict[str, Any], key: str) -> Any:
    value = attributes.get(f"{key}.value")
    mime = str(attributes.get(f"{key}.mime_type") or "")
    if "json" in mime:
        return _maybe_json(value)
    return value


def _first(attributes: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = attributes.get(key)
        if value not in (None, "", [], {}):
            return value
    return None


def _usage(attributes: dict[str, Any]) -> dict[str, Any]:
    usage: dict[str, Any] = {}
    for src, dst in (
        ("llm.token_count.prompt", "prompt_tokens"),
        ("llm.token_count.completion", "completion_tokens"),
        ("llm.token_count.total", "total_tokens"),
        ("gen_ai.usage.input_tokens", "input_tokens"),
        ("gen_ai.usage.output_tokens", "output_tokens"),
        ("gen_ai.aggregated_usage.input_tokens", "input_tokens"),
        ("gen_ai.aggregated_usage.output_tokens", "output_tokens"),
    ):
        value = attributes.get(src)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            usage.setdefault(dst, value)
    return usage


def _llm_data(attributes: dict[str, Any]) -> dict[str, Any]:
    params = _maybe_json(attributes.get("llm.invocation_parameters"))
    if not isinstance(params, dict):
        params = {}
    for key in ("temperature", "max_tokens", "top_p", "top_k", "seed", "frequency_penalty", "presence_penalty"):
        value = attributes.get(f"gen_ai.request.{key}")
        if value is not None:
            params.setdefault(key, value)
    input_messages = _unflatten(attributes, "llm.input_messages")
    if input_messages is None:
        input_messages = _unflatten(attributes, "gen_ai.input.messages")
    output_messages = _unflatten(attributes, "llm.output_messages")
    if output_messages is None:
        output_messages = _unflatten(attributes, "gen_ai.output.messages")
    data: dict[str, Any] = {
        "model": str(
            _first(attributes, "llm.model_name", "gen_ai.response.model", "gen_ai.request.model", "model")
            or "unknown"
        ),
        "input": {"messages": input_messages} if input_messages is not None else {"value": _io_value(attributes, "input")},
        "output": {"messages": output_messages}
        if output_messages is not None
        else {"value": _io_value(attributes, "output")},
        "parameters": params,
        "usage": _usage(attributes),
    }
    provider = _first(attributes, "llm.provider", "gen_ai.provider.name", "gen_ai.system", "llm.system")
    if provider is not None:
        data["provider"] = str(provider)
    finish = attributes.get("gen_ai.response.finish_reasons")
    if finish is not None:
        data["finish_reason"] = finish
    return data


def _typed_data(span_type: str, name: str, attributes: dict[str, Any], status: str) -> dict[str, Any]:
    if span_type == "llm":
        return _llm_data(attributes)
    if span_type == "tool":
        data: dict[str, Any] = {
            "tool_name": str(_first(attributes, "tool.name", "gen_ai.tool.name") or name),
            "input": _maybe_json(_first(attributes, "input.value", "gen_ai.tool.call.arguments")),
            "output": _maybe_json(_first(attributes, "output.value", "gen_ai.tool.call.result")),
            "success": status == "ok",
            "side_effects": False,
        }
        call_id = _first(attributes, "tool_call.id", "gen_ai.tool.call.id")
        if call_id is not None:
            data["tool_call_id"] = str(call_id)
        description = _first(attributes, "tool.description", "gen_ai.tool.description")
        if description is not None:
            data["description"] = description
        retry = {
            key.rsplit(".", 1)[-1]: attributes[key]
            for key in ("pydantic_ai.tool.retry.cause", "pydantic_ai.tool.retry.attempt",
                        "pydantic_ai.tool.retry.max_retries")
            if key in attributes
        }
        if retry:
            data["retry"] = retry
        return data
    if span_type == "retrieval":
        documents = _unflatten(attributes, "retrieval.documents") or []
        for doc in documents:
            if isinstance(doc, dict) and "metadata" in doc:
                doc["metadata"] = _maybe_json(doc["metadata"])
        return {
            "query": _io_value(attributes, "input"),
            "documents": documents,
            "document_count": len(documents),
            "source": name,
        }
    data = {"input": _io_value(attributes, "input"), "output": _io_value(attributes, "output")}
    if span_type == "agent":
        agent_name = _first(attributes, "gen_ai.agent.name", "agent.name", "agent_name")
        if agent_name is not None:
            data["agent_name"] = str(agent_name)
        final = attributes.get("final_result")
        if final is not None and data["output"] is None:
            data["output"] = _maybe_json(final)
        usage = _usage(attributes)
        if usage:
            data["usage"] = usage
    return data


def _timestamp(value: Any) -> str | None:
    if value is None or value == "" or value == 0 or value == "0":
        return None
    text = str(value)
    if text.isdigit() and len(text) > 12:
        from datetime import datetime, timezone

        nanos = int(text)
        return (
            datetime.fromtimestamp(nanos // 1_000_000_000, tz=timezone.utc)
            .replace(microsecond=(nanos % 1_000_000_000) // 1000)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )
    return text


def _optional_str(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value)
