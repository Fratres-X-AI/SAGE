from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sage.schema import IncidentBundle, SageSpan

# GenAI / OpenInference-aligned attribute keys (OTel semantic conventions draft).
ATTR_TRACE_ID = "sage.bundle_id"
ATTR_SPAN_TYPE = "sage.span.type"
ATTR_AGENT_ID = "sage.agent.id"
ATTR_AGENT_ROLE = "sage.agent.role"
ATTR_OPENINFERENCE_KIND = "openinference.span.kind"
ATTR_GEN_AI_SYSTEM = "gen_ai.system"
ATTR_GEN_AI_REQUEST_MODEL = "gen_ai.request.model"
ATTR_GEN_AI_USAGE_INPUT = "gen_ai.usage.input_tokens"
ATTR_GEN_AI_USAGE_OUTPUT = "gen_ai.usage.output_tokens"
ATTR_TOOL_NAME = "gen_ai.tool.name"
ATTR_RETRIEVAL_QUERY = "retrieval.query"
ATTR_OUTPUT_VALUE = "output.value"
ATTR_INPUT_VALUE = "input.value"
ATTR_BLOB_SHA = "sage.blob.sha256"


def _rfc3339_to_nanos(ts: str | None) -> int:
    if not ts:
        return 0
    try:
        # Support trailing Z
        normalized = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1_000_000_000)
    except ValueError:
        return 0


def _status_code(span: SageSpan) -> dict[str, Any]:
    if span.status in {"error", "timeout"}:
        return {"code": 2, "message": (span.error.message if span.error else span.status)}
    return {"code": 1, "message": ""}


def _kind_for_type(span_type: str) -> str:
    mapping = {
        "llm": "LLM",
        "tool": "TOOL",
        "retrieval": "RETRIEVER",
        "agent": "AGENT",
        "chain": "CHAIN",
        "guardrail": "GUARDRAIL",
        "human": "HUMAN",
        "policy": "POLICY",
        "handoff": "AGENT",
        "embedding": "EMBEDDING",
        "reranker": "RERANKER",
        "evaluator": "EVALUATOR",
        "prompt": "LLM",
    }
    return mapping.get(span_type, "UNKNOWN")


def _json_attr(value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int) and not isinstance(value, bool):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, str):
        return {"stringValue": value}
    return {"stringValue": json.dumps(value, sort_keys=True, default=str)}


def _attributes_for_span(span: SageSpan) -> list[dict[str, Any]]:
    attrs: dict[str, Any] = {
        ATTR_SPAN_TYPE: span.type,
        ATTR_OPENINFERENCE_KIND: _kind_for_type(span.type),
        ATTR_TRACE_ID: span.trace_id,
    }
    if span.agent_id:
        attrs[ATTR_AGENT_ID] = span.agent_id
    if span.agent_role:
        attrs[ATTR_AGENT_ROLE] = span.agent_role

    data = span.data or {}
    if span.type == "llm":
        attrs[ATTR_GEN_AI_SYSTEM] = data.get("system") or "sage"
        attrs[ATTR_GEN_AI_REQUEST_MODEL] = data.get("model") or "unknown"
        usage = data.get("usage") or {}
        for src, dest in (
            ("input_tokens", ATTR_GEN_AI_USAGE_INPUT),
            ("output_tokens", ATTR_GEN_AI_USAGE_OUTPUT),
        ):
            raw = usage.get(src)
            if raw is None or raw == "[REDACTED]":
                continue
            try:
                attrs[dest] = int(raw)
            except (TypeError, ValueError):
                attrs[dest] = raw
        attrs[ATTR_INPUT_VALUE] = data.get("input", span.inputs)
        attrs[ATTR_OUTPUT_VALUE] = data.get("output", span.outputs)
    elif span.type == "tool":
        attrs[ATTR_TOOL_NAME] = data.get("tool_name") or span.name
        attrs[ATTR_INPUT_VALUE] = data.get("input", span.inputs)
        attrs[ATTR_OUTPUT_VALUE] = data.get("output", span.outputs)
    elif span.type == "retrieval":
        attrs[ATTR_RETRIEVAL_QUERY] = data.get("query", span.inputs.get("query", ""))
        attrs[ATTR_OUTPUT_VALUE] = data.get("documents", span.outputs.get("documents", []))
    else:
        if span.inputs:
            attrs[ATTR_INPUT_VALUE] = span.inputs
        if span.outputs:
            attrs[ATTR_OUTPUT_VALUE] = span.outputs

    # Surface CAS refs for enterprise pipelines that prefer lazy fetch.
    for key, value in {**span.inputs, **span.outputs, **data}.items():
        if isinstance(value, dict) and "$sage_blob" in value:
            attrs[f"{ATTR_BLOB_SHA}.{key}"] = value["$sage_blob"]

    for key, value in span.attributes.items():
        attrs[f"sage.attr.{key}"] = value

    return [{"key": key, "value": _json_attr(value)} for key, value in attrs.items()]


def span_to_otel(span: SageSpan, *, resource_attrs: list[dict[str, Any]]) -> dict[str, Any]:
    start = _rfc3339_to_nanos(span.start_time)
    end = _rfc3339_to_nanos(span.end_time) or start
    return {
        "traceId": (span.trace_id or "").replace("-", "")[:32].ljust(32, "0"),
        "spanId": (span.span_id or "").replace("-", "")[:16].ljust(16, "0"),
        "parentSpanId": (span.parent_id or "").replace("-", "")[:16].ljust(16, "0")
        if span.parent_id
        else "",
        "name": span.name,
        "kind": 1,  # INTERNAL
        "startTimeUnixNano": str(start),
        "endTimeUnixNano": str(end),
        "attributes": _attributes_for_span(span),
        "status": _status_code(span),
        "events": [
            {
                "timeUnixNano": str(_rfc3339_to_nanos(event.get("timestamp"))),
                "name": event.get("name") or "event",
                "attributes": [
                    {"key": k, "value": _json_attr(v)}
                    for k, v in event.items()
                    if k not in {"name", "timestamp"}
                ],
            }
            for event in span.events
        ],
    }


def export_bundle_to_otel(
    bundle: IncidentBundle,
    *,
    service_name: str = "sage-agent",
) -> dict[str, Any]:
    """Compile a SAGE bundle into an OTLP JSON-shaped resourceSpans payload."""
    resource_attrs = [
        {"key": "service.name", "value": {"stringValue": service_name}},
        {"key": "sage.bundle_id", "value": {"stringValue": bundle.bundle_id}},
        {"key": "sage.schema_version", "value": {"stringValue": bundle.schema_version}},
        {
            "key": "sage.bundle_hash",
            "value": {"stringValue": bundle.audit.bundle_hash or ""},
        },
        {
            "key": "sage.source.framework",
            "value": {"stringValue": bundle.source.framework},
        },
    ]
    spans = [span_to_otel(span, resource_attrs=resource_attrs) for span in bundle.spans]
    return {
        "resourceSpans": [
            {
                "resource": {"attributes": resource_attrs},
                "scopeSpans": [
                    {
                        "scope": {"name": "sage", "version": bundle.schema_version},
                        "spans": spans,
                    }
                ],
            }
        ]
    }
