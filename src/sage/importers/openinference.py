from __future__ import annotations

import json
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


def load_openinference_file(path: str | Path, *, title: str | None = None) -> IncidentBundle:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return import_openinference(data, title=title or Path(path).stem)


def import_openinference(data: Any, *, title: str = "Imported trace") -> IncidentBundle:
    spans = [_convert_span(span) for span in _iter_spans(data)]
    bundle = IncidentBundle(
        title=title,
        source=BundleSource(framework="openinference", run_id=new_id("run"), environment="imported"),
        metadata={"importer": "openinference"},
        status="failed" if any(s.status == "error" for s in spans) else "completed",
    )
    for span in spans:
        if not span.trace_id:
            span.trace_id = bundle.bundle_id
        ensure_typed_data(span)
        bundle.add_span(span)
    return finalize_bundle(bundle, redact=True, status=bundle.status)


def _iter_spans(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [span for span in data if isinstance(span, dict)]
    if not isinstance(data, dict):
        raise ValueError("OpenInference import expects a dict or list of spans")
    if "spans" in data and isinstance(data["spans"], list):
        return [span for span in data["spans"] if isinstance(span, dict)]
    if "resourceSpans" in data:
        return list(_iter_otel_resource_spans(data))
    if "trace" in data:
        return _iter_spans(data["trace"])
    return [data]


def _iter_otel_resource_spans(data: dict[str, Any]) -> list[dict[str, Any]]:
    spans: list[dict[str, Any]] = []
    for resource_span in data.get("resourceSpans", []):
        for scope_span in resource_span.get("scopeSpans", []):
            for span in scope_span.get("spans", []):
                spans.append(span)
    return spans


def convert_span(span: dict[str, Any]) -> SageSpan:
    """Public converter: one OTel / OpenInference span dict → SageSpan."""
    return _convert_span(span)


def _convert_span(span: dict[str, Any]) -> SageSpan:
    attributes = _normalize_attributes(span.get("attributes") or {})
    span_type = _detect_type(span, attributes)
    status = _detect_status(span)
    inputs, outputs = _split_io(attributes)
    span_id = span.get("spanId") or span.get("id") or span.get("context", {}).get("span_id")
    err_msg = _extract_error(span, attributes)
    result = SageSpan(
        span_id=str(span_id) if span_id else new_id("span"),
        parent_id=_optional_str(span.get("parentSpanId") or span.get("parent_id")),
        type=span_type,
        name=str(span.get("name") or attributes.get("name") or span_type),
        start_time=_timestamp(span.get("startTimeUnixNano") or span.get("start_time")) or utc_now(),
        end_time=_timestamp(span.get("endTimeUnixNano") or span.get("end_time")) or utc_now(),
        status=status,
        inputs=inputs,
        outputs=outputs,
        attributes=attributes,
        error=SpanError(type="Error", message=err_msg) if err_msg else None,
        agent_id=_optional_str(attributes.get("agent_id") or attributes.get("gen_ai.agent.name")),
    )
    ensure_typed_data(result)
    return result


def _normalize_attributes(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return dict(raw)
    normalized: dict[str, Any] = {}
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict) or "key" not in item:
                continue
            normalized[str(item["key"])] = _otel_value(item.get("value"))
    return normalized


def _otel_value(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    for key in ("stringValue", "intValue", "doubleValue", "boolValue", "bytesValue"):
        if key in value:
            return value[key]
    if "arrayValue" in value:
        return [_otel_value(item) for item in value["arrayValue"].get("values", [])]
    if "kvlistValue" in value:
        return {
            item["key"]: _otel_value(item.get("value"))
            for item in value["kvlistValue"].get("values", [])
            if "key" in item
        }
    return value


def _detect_type(span: dict[str, Any], attributes: dict[str, Any]) -> Any:
    raw_kind = attributes.get("openinference.span.kind") or span.get("kind")
    if raw_kind:
        key = str(raw_kind).upper()
        if key in OPENINFERENCE_KIND_MAP:
            return OPENINFERENCE_KIND_MAP[key]
        return normalize_type(str(raw_kind))
    operation = attributes.get("gen_ai.operation.name")
    if operation:
        mapped = GEN_AI_OPERATION_MAP.get(str(operation))
        if mapped:
            return mapped
    return "chain"


def _detect_status(span: dict[str, Any]) -> Any:
    status = span.get("status")
    if isinstance(status, dict):
        code = str(status.get("code") or "").upper()
        if code in {"STATUS_CODE_ERROR", "ERROR", "2"}:
            return "error"
        if code in {"STATUS_CODE_OK", "OK", "1"}:
            return "ok"
    raw = str(status or span.get("statusCode") or "ok")
    try:
        return normalize_status(raw)
    except ValueError:
        return "ok"


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


def _timestamp(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    if text.isdigit() and len(text) > 12:
        seconds = int(text) / 1_000_000_000
        from datetime import datetime, timezone

        return (
            datetime.fromtimestamp(seconds, tz=timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )
    return text


def _optional_str(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def _extract_error(span: dict[str, Any], attributes: dict[str, Any]) -> str | None:
    if "error.type" in attributes:
        return str(attributes["error.type"])
    status = span.get("status")
    if isinstance(status, dict) and status.get("message"):
        return str(status["message"])
    return None
