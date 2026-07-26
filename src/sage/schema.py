from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Literal

SCHEMA_VERSION = "1.0"
LEGACY_SCHEMA_VERSION = "sage.bundle.v1"

SpanType = Literal[
    "agent",
    "chain",
    "embedding",
    "evaluator",
    "guardrail",
    "human",
    "llm",
    "policy",
    "prompt",
    "reranker",
    "retrieval",
    "tool",
    "handoff",
    "custom",
]

# Backward-compatible uppercase aliases used by older call sites.
SpanKind = Literal[
    "AGENT",
    "CHAIN",
    "EMBEDDING",
    "EVALUATOR",
    "GUARDRAIL",
    "HUMAN",
    "LLM",
    "POLICY",
    "PROMPT",
    "RERANKER",
    "RETRIEVER",
    "TOOL",
    "HANDOFF",
    "CUSTOM",
]

SpanStatus = Literal["ok", "error", "cancelled", "timeout"]
BundleStatus = Literal["completed", "failed", "partial"]

KIND_TO_TYPE = {
    "AGENT": "agent",
    "CHAIN": "chain",
    "EMBEDDING": "embedding",
    "EVALUATOR": "evaluator",
    "GUARDRAIL": "guardrail",
    "HUMAN": "human",
    "LLM": "llm",
    "POLICY": "policy",
    "PROMPT": "prompt",
    "RERANKER": "reranker",
    "RETRIEVER": "retrieval",
    "TOOL": "tool",
    "HANDOFF": "handoff",
    "CUSTOM": "custom",
}
TYPE_TO_KIND = {v: k for k, v in KIND_TO_TYPE.items()}
TYPE_TO_KIND["retrieval"] = "RETRIEVER"

STATUS_ALIASES = {
    "OK": "ok",
    "ERROR": "error",
    "UNSET": "ok",
    "BLOCKED": "error",
    "CANCELLED": "cancelled",
    "TIMEOUT": "timeout",
    "ok": "ok",
    "error": "error",
    "cancelled": "cancelled",
    "timeout": "timeout",
}


def utc_now() -> str:
    from sage.clock import utc_now as _clock_now

    return _clock_now()


def new_id(prefix: str) -> str:
    from uuid import uuid4

    return f"{prefix}_{uuid4().hex}"


@dataclass
class SpanError:
    type: str
    message: str
    stack: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {"type": self.type, "message": self.message}
        if self.stack is not None:
            payload["stack"] = self.stack
        return payload

    @classmethod
    def from_value(cls, value: Any) -> "SpanError | None":
        if value is None:
            return None
        if isinstance(value, SpanError):
            return value
        if isinstance(value, dict):
            return cls(
                type=str(value.get("type") or "Error"),
                message=str(value.get("message") or ""),
                stack=value.get("stack"),
            )
        return cls(type="Error", message=str(value))


@dataclass
class BundleSource:
    framework: str = "custom"
    run_id: str = ""
    environment: str = "local"

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "run_id": self.run_id,
            "environment": self.environment,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None, *, run_id: str = "") -> "BundleSource":
        data = data or {}
        return cls(
            framework=str(data.get("framework") or "custom"),
            run_id=str(data.get("run_id") or run_id or ""),
            environment=str(data.get("environment") or "local"),
        )


@dataclass
class AuditBlock:
    chain: list[dict[str, Any]] = field(default_factory=list)
    bundle_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"chain": self.chain, "bundle_hash": self.bundle_hash}


@dataclass
class SageSpan:
    """A normalized unit of work inside an agent incident bundle."""

    type: SpanType
    name: str
    span_id: str = field(default_factory=lambda: new_id("span"))
    parent_id: str | None = None
    trace_id: str = ""
    start_time: str = field(default_factory=utc_now)
    end_time: str | None = None
    status: SpanStatus = "ok"
    error: SpanError | None = None
    agent_id: str | None = None
    agent_role: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    inputs: dict[str, Any] = field(default_factory=dict)
    outputs: dict[str, Any] = field(default_factory=dict)
    is_suspected_root_cause: bool = False
    contribution_score: float | None = None
    failure_context: str | None = None

    def __post_init__(self) -> None:
        # Allow construction with legacy kind= via type already set.
        if not self.trace_id:
            self.trace_id = ""

    @property
    def id(self) -> str:
        return self.span_id

    @id.setter
    def id(self, value: str) -> None:
        self.span_id = value

    @property
    def kind(self) -> str:
        return TYPE_TO_KIND.get(self.type, self.type.upper())

    @classmethod
    def from_kind(
        cls,
        kind: str,
        name: str,
        **kwargs: Any,
    ) -> "SageSpan":
        normalized = kind.upper()
        if normalized == "RETRIEVER":
            span_type: SpanType = "retrieval"
        else:
            span_type = KIND_TO_TYPE.get(normalized, "custom")  # type: ignore[assignment]
        return cls(type=span_type, name=name, **kwargs)

    def finish(
        self,
        *,
        status: SpanStatus | str = "ok",
        outputs: dict[str, Any] | None = None,
        error: BaseException | str | SpanError | dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        self.end_time = utc_now()
        self.status = normalize_status(status)
        if outputs is not None:
            self.outputs = outputs
            if "output" not in self.data:
                self.data["output"] = outputs
        if data is not None:
            self.data.update(data)
        if error is not None:
            self.status = "error"
            self.error = SpanError.from_value(error)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "span_id": self.span_id,
            "parent_id": self.parent_id,
            "trace_id": self.trace_id,
            "type": self.type,
            "kind": self.kind,  # compatibility mirror
            "name": self.name,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "status": self.status,
            "error": self.error.to_dict() if self.error else None,
            "agent_id": self.agent_id,
            "agent_role": self.agent_role,
            "attributes": self.attributes,
            "events": self.events,
            "data": self.data,
            "inputs": self.inputs,
            "outputs": self.outputs,
            "is_suspected_root_cause": self.is_suspected_root_cause,
            "contribution_score": self.contribution_score,
            "failure_context": self.failure_context,
        }
        return payload

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, default_trace_id: str = "") -> "SageSpan":
        raw_type = data.get("type") or data.get("kind")
        if not raw_type:
            raise ValueError("span type/kind is required")
        span_type = normalize_type(str(raw_type))
        span_id = str(data.get("span_id") or data.get("id") or "")
        if not span_id:
            raise ValueError("span_id is required")
        err = SpanError.from_value(data.get("error"))
        span = cls(
            span_id=span_id,
            parent_id=_optional_str(data.get("parent_id")),
            trace_id=str(data.get("trace_id") or default_trace_id or ""),
            type=span_type,
            name=str(data.get("name") or ""),
            start_time=str(data.get("start_time") or utc_now()),
            end_time=_optional_str(data.get("end_time")),
            status=normalize_status(data.get("status", "ok")),
            error=err,
            agent_id=_optional_str(data.get("agent_id")),
            agent_role=_optional_str(data.get("agent_role")),
            attributes=dict(data.get("attributes") or {}),
            events=list(data.get("events") or []),
            data=dict(data.get("data") or {}),
            inputs=dict(data.get("inputs") or {}),
            outputs=dict(data.get("outputs") or {}),
            is_suspected_root_cause=bool(data.get("is_suspected_root_cause", False)),
            contribution_score=data.get("contribution_score"),
            failure_context=_optional_str(data.get("failure_context")),
        )
        ensure_typed_data(span)
        span.validate(strict=True)
        return span

    def validate(self, *, strict: bool = True) -> None:
        if not self.span_id:
            raise ValueError("span_id is required")
        if not self.name:
            raise ValueError(f"span {self.span_id} is missing a name")
        if self.type not in VALID_SPAN_TYPES:
            raise ValueError(f"span {self.span_id} has unsupported type {self.type!r}")
        if self.status not in VALID_STATUSES:
            raise ValueError(f"span {self.span_id} has unsupported status {self.status!r}")
        if not self.trace_id and strict:
            raise ValueError(f"span {self.span_id} is missing trace_id")
        if strict:
            _validate_typed_payload(self)


@dataclass
class IncidentBundle:
    """A portable, auditable record of an agent run or failure."""

    title: str
    bundle_id: str = field(default_factory=lambda: new_id("bundle"))
    schema_version: str = SCHEMA_VERSION
    created_at: str = field(default_factory=utc_now)
    source: BundleSource = field(default_factory=BundleSource)
    status: BundleStatus = "completed"
    root_cause_hint: str | list[str] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    spans: list[SageSpan] = field(default_factory=list)
    redactions: list[dict[str, Any]] = field(default_factory=list)
    redaction_policy: dict[str, Any] = field(default_factory=dict)
    audit: AuditBlock = field(default_factory=AuditBlock)

    def __post_init__(self) -> None:
        if not self.source.run_id:
            self.source.run_id = new_id("run")

    @property
    def run_id(self) -> str:
        return self.source.run_id

    @run_id.setter
    def run_id(self, value: str) -> None:
        self.source.run_id = value

    @property
    def audit_chain(self) -> list[dict[str, Any]]:
        return self.audit.chain

    @audit_chain.setter
    def audit_chain(self, value: list[dict[str, Any]]) -> None:
        self.audit.chain = value

    def add_span(self, span: SageSpan) -> SageSpan:
        if not span.trace_id:
            span.trace_id = self.bundle_id
        span.validate(strict=False)
        self.spans.append(span)
        return span

    def extend(self, spans: Iterable[SageSpan]) -> None:
        for span in spans:
            self.add_span(span)

    def sort_spans(self) -> None:
        self.spans.sort(key=lambda s: (s.start_time or "", s.span_id))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "bundle_id": self.bundle_id,
            "title": self.title,
            "created_at": self.created_at,
            "source": self.source.to_dict(),
            "status": self.status,
            "root_cause_hint": self.root_cause_hint,
            "metadata": self.metadata,
            "spans": [span.to_dict() for span in self.spans],
            "redactions": self.redactions,
            "redaction_policy": self.redaction_policy,
            "audit": self.audit.to_dict(),
            # Compatibility mirrors for older readers
            "run_id": self.run_id,
            "audit_chain": self.audit.chain,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IncidentBundle":
        version = str(data.get("schema_version") or SCHEMA_VERSION)
        if version == LEGACY_SCHEMA_VERSION:
            data = migrate_v1_to_v1_0(data)
            version = SCHEMA_VERSION
        if version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema version {version!r}")

        source = BundleSource.from_dict(data.get("source"), run_id=str(data.get("run_id") or ""))
        bundle_id = str(data.get("bundle_id") or new_id("bundle"))
        audit_raw = data.get("audit") or {}
        chain = list(audit_raw.get("chain") or data.get("audit_chain") or [])
        bundle = cls(
            schema_version=SCHEMA_VERSION,
            bundle_id=bundle_id,
            title=str(data.get("title") or "Untitled incident"),
            created_at=str(data.get("created_at") or utc_now()),
            source=source,
            status=normalize_bundle_status(data.get("status", "completed")),
            root_cause_hint=data.get("root_cause_hint"),
            metadata=dict(data.get("metadata") or {}),
            spans=[
                SageSpan.from_dict(span, default_trace_id=bundle_id) for span in data.get("spans", [])
            ],
            redactions=list(data.get("redactions") or []),
            redaction_policy=dict(data.get("redaction_policy") or {}),
            audit=AuditBlock(chain=chain, bundle_hash=str(audit_raw.get("bundle_hash") or "")),
        )
        if not bundle.source.run_id:
            bundle.source.run_id = new_id("run")
        bundle.validate(strict=True)
        return bundle

    def validate(self, *, strict: bool = True) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema version {self.schema_version!r}")
        if not self.bundle_id:
            raise ValueError("bundle_id is required")
        if not self.source.run_id:
            raise ValueError("source.run_id is required")
        if self.status not in VALID_BUNDLE_STATUSES:
            raise ValueError(f"unsupported bundle status {self.status!r}")
        seen: set[str] = set()
        for span in self.spans:
            if not span.trace_id:
                span.trace_id = self.bundle_id
            span.validate(strict=strict)
            if span.span_id in seen:
                raise ValueError(f"duplicate span_id {span.span_id}")
            seen.add(span.span_id)


def normalize_type(value: str) -> SpanType:
    lowered = value.lower()
    if lowered == "retriever":
        return "retrieval"
    if lowered in VALID_SPAN_TYPES:
        return lowered  # type: ignore[return-value]
    upper = value.upper()
    if upper in KIND_TO_TYPE:
        return KIND_TO_TYPE[upper]  # type: ignore[return-value]
    raise ValueError(f"unsupported span type {value!r}")


def normalize_status(value: Any) -> SpanStatus:
    key = str(value)
    if key not in STATUS_ALIASES:
        raise ValueError(f"unsupported span status {value!r}")
    return STATUS_ALIASES[key]  # type: ignore[return-value]


def normalize_bundle_status(value: Any) -> BundleStatus:
    key = str(value).lower()
    if key not in VALID_BUNDLE_STATUSES:
        raise ValueError(f"unsupported bundle status {value!r}")
    return key  # type: ignore[return-value]


def _optional_str(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def ensure_typed_data(span: SageSpan) -> SageSpan:
    """Fill type-specific data from inputs/outputs/attributes when missing."""
    if not span.data:
        span.data = _infer_data_from_legacy(span)
    else:
        # Ensure common mirrors exist without wiping richer payloads.
        inferred = _infer_data_from_legacy(span)
        for key, value in inferred.items():
            span.data.setdefault(key, value)
    if span.type == "llm":
        span.data.setdefault("model", "unknown")
        span.data.setdefault("input", span.inputs or {})
        span.data.setdefault("output", span.outputs or {})
        span.data.setdefault("parameters", {})
        span.data.setdefault("usage", {})
    elif span.type == "tool":
        span.data.setdefault("tool_name", span.name)
        span.data.setdefault("input", span.inputs or {})
        span.data.setdefault("output", span.outputs or {})
        span.data.setdefault("success", span.status == "ok")
        span.data.setdefault("side_effects", False)
    elif span.type == "retrieval":
        span.data.setdefault("query", span.inputs.get("query", span.inputs))
        span.data.setdefault("documents", span.outputs.get("documents", []))
        span.data.setdefault("source", span.name)
    elif span.type == "policy":
        span.data.setdefault("policy_name", span.name)
        span.data.setdefault("rule_id", span.name)
        span.data.setdefault("decision", span.outputs.get("decision", "allow"))
        span.data.setdefault("checked_input", span.inputs or {})
    elif span.type == "handoff":
        span.data.setdefault("from_agent", span.agent_id or "unknown")
        span.data.setdefault("to_agent", span.attributes.get("to_agent") or "unknown")
        span.data.setdefault("context_passed", span.inputs or {})
    elif span.type == "agent":
        span.data.setdefault("goal", span.inputs.get("goal"))
    return span


def _infer_data_from_legacy(span: SageSpan) -> dict[str, Any]:
    if span.type == "llm":
        return {
            "model": span.attributes.get("model") or span.outputs.get("model") or "unknown",
            "input": span.inputs,
            "output": span.outputs,
            "parameters": span.attributes.get("parameters") or {},
            "usage": span.attributes.get("usage") or {},
            "finish_reason": span.attributes.get("finish_reason") or span.outputs.get("finish_reason"),
        }
    if span.type == "tool":
        return {
            "tool_name": span.name,
            "input": span.inputs,
            "output": span.outputs,
            "success": span.status == "ok",
            "side_effects": span.attributes.get("side_effects", False),
            "latency_ms": span.attributes.get("latency_ms"),
        }
    if span.type == "retrieval":
        return {
            "query": span.inputs.get("query") or span.inputs,
            "documents": span.outputs.get("documents") or [],
            "source": span.attributes.get("source") or span.name,
        }
    if span.type == "policy":
        return {
            "policy_name": span.name,
            "rule_id": span.attributes.get("rule_id") or span.name,
            "decision": span.outputs.get("decision") or "allow",
            "reason": span.error.message if span.error else span.outputs.get("reason"),
            "checked_input": span.inputs,
        }
    if span.type in {"agent", "handoff"}:
        payload = {
            "goal": span.inputs.get("goal") or span.attributes.get("goal"),
            "plan_step": span.attributes.get("plan_step"),
            "next_action": span.outputs.get("next_action") or span.attributes.get("next_action"),
            "state_hash": span.attributes.get("state_hash"),
        }
        if span.type == "handoff":
            payload.update(
                {
                    "from_agent": span.attributes.get("from_agent") or span.agent_id,
                    "to_agent": span.attributes.get("to_agent"),
                    "context_passed": span.outputs.get("context_passed") or span.inputs,
                }
            )
        return payload
    return {"input": span.inputs, "output": span.outputs}


def _validate_typed_payload(span: SageSpan) -> None:
    data = span.data or {}
    if span.type == "llm":
        for key in ("model", "input", "output"):
            if key not in data:
                raise ValueError(f"llm span {span.span_id} missing data.{key}")
    elif span.type == "tool":
        for key in ("tool_name", "input", "output", "success"):
            if key not in data:
                raise ValueError(f"tool span {span.span_id} missing data.{key}")
    elif span.type == "retrieval":
        for key in ("query", "documents"):
            if key not in data:
                raise ValueError(f"retrieval span {span.span_id} missing data.{key}")
    elif span.type == "policy":
        if "decision" not in data:
            raise ValueError(f"policy span {span.span_id} missing data.decision")
        if not (data.get("rule_id") or data.get("policy_name")):
            raise ValueError(f"policy span {span.span_id} missing rule_id/policy_name")
    elif span.type == "handoff":
        for key in ("from_agent", "to_agent"):
            if key not in data:
                raise ValueError(f"handoff span {span.span_id} missing data.{key}")


def migrate_v1_to_v1_0(data: dict[str, Any]) -> dict[str, Any]:
    """One-shot migrator from sage.bundle.v1 flat spans to schema 1.0."""
    run_id = str(data.get("run_id") or new_id("run"))
    bundle_id = str(data.get("bundle_id") or new_id("bundle"))
    spans_out = []
    for raw in data.get("spans", []):
        kind = str(raw.get("kind") or raw.get("type") or "custom")
        span_type = normalize_type(kind)
        status = normalize_status(raw.get("status", "ok"))
        err = SpanError.from_value(raw.get("error"))
        span = {
            "span_id": raw.get("span_id") or raw.get("id") or new_id("span"),
            "parent_id": raw.get("parent_id"),
            "trace_id": raw.get("trace_id") or bundle_id,
            "type": span_type,
            "name": raw.get("name") or span_type,
            "start_time": raw.get("start_time") or utc_now(),
            "end_time": raw.get("end_time"),
            "status": status,
            "error": err.to_dict() if err else None,
            "agent_id": raw.get("agent_id"),
            "agent_role": raw.get("agent_role"),
            "attributes": dict(raw.get("attributes") or {}),
            "events": list(raw.get("events") or []),
            "inputs": dict(raw.get("inputs") or {}),
            "outputs": dict(raw.get("outputs") or {}),
            "data": dict(raw.get("data") or {}),
            "is_suspected_root_cause": raw.get("is_suspected_root_cause", False),
            "contribution_score": raw.get("contribution_score"),
            "failure_context": raw.get("failure_context"),
        }
        if not span["data"]:
            span["data"] = _infer_data_from_legacy(
                SageSpan(
                    type=span_type,
                    name=str(span["name"]),
                    span_id=str(span["span_id"]),
                    trace_id=bundle_id,
                    status=status,
                    error=err,
                    attributes=span["attributes"],
                    inputs=span["inputs"],
                    outputs=span["outputs"],
                )
            )
        spans_out.append(span)

    return {
        "schema_version": SCHEMA_VERSION,
        "bundle_id": bundle_id,
        "title": data.get("title") or "Untitled incident",
        "created_at": data.get("created_at") or utc_now(),
        "source": {
            "framework": (data.get("metadata") or {}).get("framework", "custom"),
            "run_id": run_id,
            "environment": (data.get("metadata") or {}).get("environment", "local"),
        },
        "status": data.get("status") or ("failed" if any(s.get("status") == "error" for s in spans_out) else "completed"),
        "root_cause_hint": data.get("root_cause_hint"),
        "metadata": dict(data.get("metadata") or {}),
        "spans": spans_out,
        "redactions": list(data.get("redactions") or []),
        "redaction_policy": dict(data.get("redaction_policy") or {}),
        "audit": {
            "chain": list((data.get("audit") or {}).get("chain") or data.get("audit_chain") or []),
            "bundle_hash": (data.get("audit") or {}).get("bundle_hash") or "",
        },
    }


VALID_SPAN_TYPES = set(SpanType.__args__)  # type: ignore[attr-defined]
VALID_STATUSES = set(SpanStatus.__args__)  # type: ignore[attr-defined]
VALID_BUNDLE_STATUSES = set(BundleStatus.__args__)  # type: ignore[attr-defined]
VALID_SPAN_KINDS = set(SpanKind.__args__)  # type: ignore[attr-defined]
