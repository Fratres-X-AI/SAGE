"""PydanticAI adapter for SAGE: records PydanticAI's OpenTelemetry spans.

Tested against ``pydantic-ai-slim==2.68.0`` with ``opentelemetry-sdk==1.45.2`` (the
``pydantic-ai`` extra)::

    pip install "sage-incident-bundles[pydantic-ai]"

Usage::

    from pydantic_ai import Agent
    from sage.adapters.pydantic_ai import SagePydanticAI

    sage = SagePydanticAI(trace_id="ticket-123", journal_dir=".sage/runs/ticket-123")
    agent = sage.instrument(Agent("openai:gpt-4o", name="support"))
    with sage:
        agent.run_sync("Where is my order?")
    sage.assert_complete()
    sage.export("ticket-123.sage.json")

``instrument(agent)`` sets ``agent.instrument`` to ``InstrumentationSettings`` bound to a private
``TracerProvider``, so nothing is sent to a global exporter. ``instrument_all()`` does the same
for every agent via ``Agent.instrument_all``. To keep an existing provider (for example Logfire),
add ``sage.span_processor`` to it instead.

Spans are converted by ``sage.importers.openinference.convert_span`` (GenAI conventions):
``invoke_agent`` → agent, ``chat`` → llm, ``execute_tool`` → tool; anything else → chain.
A tool that raises ``ModelRetry`` is an ``error`` span with ``data["retry"]`` (PydanticAI marks
it ERROR); the run itself may still succeed. Redaction happens in the recorder before disk.
"""

from __future__ import annotations

import threading
from typing import Any

from sage.errors import SageError
from sage.importers.openinference import convert_span
from sage.recorder import SageRecorder
from sage.schema import normalize_type

INSTALL_HINT = (
    'The PydanticAI adapter needs pydantic-ai-slim and opentelemetry-sdk: '
    'pip install "sage-incident-bundles[pydantic-ai]"'
)

try:  # Optional dependency: core SAGE must import without PydanticAI / the OTel SDK.
    from opentelemetry.sdk.trace import SpanProcessor as _SpanProcessorBase
    from opentelemetry.sdk.trace import TracerProvider as _TracerProvider

    OTEL_SDK_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised via sys.modules simulation
    OTEL_SDK_AVAILABLE = False
    _TracerProvider = None  # type: ignore[assignment,misc]

    class _SpanProcessorBase:  # type: ignore[no-redef]
        pass


try:
    from pydantic_ai.models.instrumented import InstrumentationSettings as _InstrumentationSettings

    PYDANTIC_AI_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised via sys.modules simulation
    PYDANTIC_AI_AVAILABLE = False
    _InstrumentationSettings = None  # type: ignore[assignment,misc]


class CaptureIncompleteError(SageError):
    """PydanticAI capture is incomplete or hit an internal error; do not hand off."""


def _hex(value: int, width: int) -> str:
    return format(value, f"0{width}x")


def readable_span_to_dict(span: Any) -> dict[str, Any]:
    """OTLP-shaped dict for an OpenTelemetry SDK ``ReadableSpan`` (input to ``convert_span``)."""
    ctx = span.get_span_context()
    parent = span.parent
    events = [
        {"name": e.name, "timeUnixNano": e.timestamp, "attributes": dict(e.attributes or {})}
        for e in span.events or ()
    ]
    scope = getattr(span, "instrumentation_scope", None)
    out: dict[str, Any] = {
        "traceId": _hex(ctx.trace_id, 32),
        "spanId": _hex(ctx.span_id, 16),
        "parentSpanId": _hex(parent.span_id, 16) if parent is not None else "",
        "name": span.name,
        "kind": int(getattr(span.kind, "value", 0) or 0),
        "startTimeUnixNano": span.start_time,
        "endTimeUnixNano": span.end_time,
        "attributes": dict(span.attributes or {}),
        "status": {
            "code": int(getattr(span.status.status_code, "value", 0) or 0),
            "message": span.status.description or "",
        },
        "events": events,
    }
    if scope is not None and getattr(scope, "name", None):
        out["_scope"] = {"name": scope.name, "version": getattr(scope, "version", None)}
    return out


class SageSpanProcessor(_SpanProcessorBase):
    """OpenTelemetry ``SpanProcessor`` that opens a SAGE span on start and closes it on end."""

    def __init__(self, owner: "SagePydanticAI") -> None:
        self._owner = owner

    def on_start(self, span: Any, parent_context: Any = None) -> None:
        self._owner._guard("on_start", self._owner._span_start, span)

    def on_end(self, span: Any) -> None:
        self._owner._guard("on_end", self._owner._span_end, span)

    def shutdown(self) -> None:
        return None

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        self._owner.recorder.flush_journal()
        return True


class SagePydanticAI:
    """Records PydanticAI agent runs (agent, model requests, tool calls) into a ``SageRecorder``."""

    def __init__(
        self,
        recorder: SageRecorder | None = None,
        *,
        trace_id: str | None = None,
        journal_dir: str | None = None,
        journal_durability: str | None = None,
        include_content: bool = True,
    ) -> None:
        if not (OTEL_SDK_AVAILABLE and PYDANTIC_AI_AVAILABLE):
            raise ImportError(INSTALL_HINT)
        self.recorder = recorder or SageRecorder(
            title="pydantic-ai",
            trace_id=trace_id,
            framework="pydantic-ai",
            journal_dir=journal_dir,
            journal_durability=journal_durability,
            register_trace=True,
        )
        self._lock = threading.Lock()
        self._spans: dict[str, str] = {}
        self._unknown: list[tuple[str, str]] = []
        self._capture_errors: list[tuple[str, str]] = []
        self._capture_exceptions: list[BaseException] = []
        self._entered = False
        self.span_processor = SageSpanProcessor(self)
        self.tracer_provider = _TracerProvider()
        self.tracer_provider.add_span_processor(self.span_processor)
        self.settings = _InstrumentationSettings(
            tracer_provider=self.tracer_provider, include_content=include_content
        )

    def instrument(self, agent: Any) -> Any:
        """Route one agent's spans to SAGE; returns the agent."""
        agent.instrument = self.settings
        return agent

    def instrument_all(self) -> None:
        """Route every agent without its own instrumentation to SAGE (``Agent.instrument_all``)."""
        from pydantic_ai import Agent

        Agent.instrument_all(self.settings)

    def __enter__(self) -> "SagePydanticAI":
        self.recorder.__enter__()
        self._entered = True
        return self

    def __exit__(self, *args: Any) -> None:
        if self._entered:
            self.recorder.__exit__(*args)
            self._entered = False

    @property
    def open_spans(self) -> list[str]:
        with self._lock:
            return sorted(self._spans)

    def span_id_for(self, otel_span_id: str) -> str | None:
        """SAGE span id for a 16-hex-digit OpenTelemetry span id."""
        with self._lock:
            return self._spans.get(otel_span_id)

    def assert_complete(self) -> None:
        """Raise ``CaptureIncompleteError`` unless every observed span was closed cleanly."""
        with self._lock:
            open_ids = sorted(self._spans)
            unknown = list(self._unknown)
            errors = list(self._capture_errors)
        if not (open_ids or unknown or errors):
            return
        parts = []
        if open_ids:
            parts.append(f"open={len(open_ids)} {open_ids}")
        if unknown:
            parts.append(f"unknown_events={len(unknown)} {[f'{e}:{i}' for e, i in unknown]}")
        if errors:
            parts.append(f"capture_errors={len(errors)} {[f'{e}:{k}' for e, k in errors]}")
        raise CaptureIncompleteError("PydanticAI capture incomplete: " + "; ".join(parts))

    def finalize(self, **kwargs: Any):
        return self.recorder.finalize(**kwargs)

    def export(self, path: Any, **kwargs: Any):
        return self.recorder.export(path, **kwargs)

    def _guard(self, event: str, fn: Any, *args: Any) -> None:
        try:
            fn(*args)
        except Exception as exc:
            with self._lock:
                self._capture_errors.append((event, type(exc).__name__))
                self._capture_exceptions.append(exc)

    def _span_start(self, span: Any) -> None:
        ctx = span.get_span_context()
        key = _hex(ctx.span_id, 16)
        parent_key = _hex(span.parent.span_id, 16) if span.parent is not None else None
        draft = convert_span({"name": span.name, "attributes": dict(span.attributes or {})})
        with self._lock:
            if key in self._spans:
                self._capture_errors.append(("on_start", "DuplicateSpanStart"))
                return
            parent = self._spans.get(parent_key) if parent_key else None
            sage_span = self.recorder.start_span(
                draft.type,
                span.name,
                parent_id=parent,
                attributes={"otel.span_id": key, "otel.trace_id": _hex(ctx.trace_id, 32)},
                agent_id=draft.agent_id,
            )
            sage_span.parent_id = parent
            self._spans[key] = sage_span.span_id

    def _span_end(self, span: Any) -> None:
        converted = convert_span(readable_span_to_dict(span))
        key = _hex(span.get_span_context().span_id, 16)
        with self._lock:
            span_id = self._spans.pop(key, None)
            if span_id is None:
                self._unknown.append(("on_end", key))
                return
            target = self.recorder._get_span(span_id)
            target.type = normalize_type(converted.type)
            target.name = converted.name
            target.inputs = converted.inputs
            target.attributes = {**converted.attributes, **target.attributes}
            target.events = converted.events
            target.agent_id = target.agent_id or converted.agent_id
            target.data = {}
            self.recorder.end_span(
                span_id,
                status=converted.status,
                outputs=converted.outputs,
                error=converted.error,
                data=converted.data,
            )
