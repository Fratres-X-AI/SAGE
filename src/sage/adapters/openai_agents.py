"""OpenAI Agents SDK adapter for SAGE: a tracing processor that records SDK spans.

Tested against ``openai-agents==0.24.0`` (the ``openai-agents`` extra)::

    pip install "sage-incident-bundles[openai-agents]"

Usage::

    from agents import Agent, Runner, set_trace_processors
    from sage.adapters.openai_agents import SageOpenAIAgentsProcessor

    processor = SageOpenAIAgentsProcessor(trace_id="ticket-123", journal_dir=".sage/runs/ticket-123")
    set_trace_processors([processor])  # or add_trace_processor(processor) to keep the OpenAI exporter
    with processor:
        Runner.run_sync(agent, "Where is my order?")
    processor.assert_complete()
    processor.export("ticket-123.sage.json")

Each SDK trace becomes a ``chain`` span; SDK spans nest under it by their ``parent_id``.
Span data mapping (``span_data.type`` → SAGE type): ``agent`` → agent, ``generation`` and
``response`` → llm, ``function`` → tool, ``handoff`` → handoff, ``guardrail`` → guardrail,
``task`` / ``turn`` (exported as custom) → chain, ``mcp_tools`` and ``custom`` → custom,
``transcription`` / ``speech`` → llm, ``speech_group`` → chain.

A triggered guardrail is recorded with status ``error`` (type ``GuardrailTripwireTriggered``) and
``data["triggered"] = True``. Span errors set by the SDK (``span.error``) become span errors.

The SDK only records model inputs/outputs when ``RunConfig.trace_include_sensitive_data`` is true
(the default). Redaction happens in the recorder, before anything reaches disk.
The SDK swallows processor exceptions, so capture failures are collected and raised by
``assert_complete()``.
"""

from __future__ import annotations

import threading
from typing import Any

from sage.errors import SageError
from sage.recorder import SageRecorder

INSTALL_HINT = 'The OpenAI Agents adapter needs openai-agents: pip install "sage-incident-bundles[openai-agents]"'

try:  # Optional dependency: core SAGE must import without the Agents SDK.
    from agents.tracing import TracingProcessor as _ProcessorBase

    OPENAI_AGENTS_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised via sys.modules simulation
    OPENAI_AGENTS_AVAILABLE = False

    class _ProcessorBase:  # type: ignore[no-redef]
        pass


SPAN_TYPE_MAP = {
    "agent": "agent",
    "generation": "llm",
    "response": "llm",
    "function": "tool",
    "handoff": "handoff",
    "guardrail": "guardrail",
    "task": "chain",
    "turn": "chain",
    "custom": "custom",
    "mcp_tools": "custom",
    "transcription": "llm",
    "speech": "llm",
    "speech_group": "chain",
}

_MAX_DEPTH = 8
_MAX_REPR = 200


class CaptureIncompleteError(SageError):
    """OpenAI Agents capture is incomplete or hit an internal error; do not hand off."""


def _jsonable(value: Any, depth: int = 0) -> Any:
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if depth >= _MAX_DEPTH:
        return {"type": type(value).__name__, "truncated": True}
    if isinstance(value, dict):
        return {str(k): _jsonable(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v, depth + 1) for v in value]
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        try:
            return _jsonable(dump(mode="json", exclude_none=True), depth + 1)
        except Exception:
            pass
    try:
        from dataclasses import asdict, is_dataclass

        if is_dataclass(value) and not isinstance(value, type):
            return _jsonable(asdict(value), depth + 1)
    except Exception:
        pass
    try:
        text = repr(value)
    except Exception:
        text = "<unrepresentable>"
    return {"type": type(value).__name__, "repr": text[:_MAX_REPR]}


def _sdk_type(span_data: Any) -> str:
    kind = str(getattr(span_data, "type", "custom") or "custom")
    return kind


def _span_name(sdk_type: str, span_data: Any) -> str:
    if sdk_type == "handoff":
        return f"handoff:{getattr(span_data, 'from_agent', None) or '?'}->{getattr(span_data, 'to_agent', None) or '?'}"
    if sdk_type == "turn":
        return f"turn {getattr(span_data, 'turn', '?')}: {getattr(span_data, 'agent_name', '')}".strip()
    if sdk_type in {"generation", "response", "transcription", "speech"}:
        model = getattr(span_data, "model", None)
        if model is None and sdk_type == "response":
            model = getattr(getattr(span_data, "response", None), "model", None)
        return f"{sdk_type}:{model}" if model else sdk_type
    if sdk_type == "mcp_tools":
        return f"mcp_tools:{getattr(span_data, 'server', None) or '?'}"
    name = getattr(span_data, "name", None)
    return str(name) if name else sdk_type


def _start_payload(sdk_type: str, span_data: Any) -> tuple[dict[str, Any], dict[str, Any], str | None]:
    """inputs, data and agent_id known when the span starts."""
    if sdk_type == "agent":
        name = getattr(span_data, "name", None)
        data = {
            "agent_name": name,
            "handoffs": _jsonable(getattr(span_data, "handoffs", None)),
            "tools": _jsonable(getattr(span_data, "tools", None)),
            "output_type": getattr(span_data, "output_type", None),
        }
        return {}, data, name
    if sdk_type == "handoff":
        frm, to = getattr(span_data, "from_agent", None), getattr(span_data, "to_agent", None)
        return {}, {"from_agent": frm or "unknown", "to_agent": to or "unknown", "context_passed": {}}, frm
    if sdk_type == "function":
        name = str(getattr(span_data, "name", "") or "function")
        return {"input": getattr(span_data, "input", None)}, {"tool_name": name}, None
    return {}, {}, None


def _llm_end(sdk_type: str, span_data: Any) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if sdk_type == "response":
        response = getattr(span_data, "response", None)
        model = getattr(response, "model", None) if response is not None else None
        inputs = {"input": _jsonable(getattr(span_data, "input", None))}
        outputs = {"output": _jsonable(getattr(response, "output", None)) if response is not None else None}
        data = {
            "model": str(model or "unknown"),
            "response_id": getattr(response, "id", None) if response is not None else None,
            "usage": _jsonable(getattr(span_data, "usage", None) or getattr(response, "usage", None) or {}),
        }
        return inputs, outputs, data
    if sdk_type == "generation":
        inputs = {"messages": _jsonable(getattr(span_data, "input", None))}
        outputs = {"messages": _jsonable(getattr(span_data, "output", None))}
        data = {
            "model": str(getattr(span_data, "model", None) or "unknown"),
            "parameters": _jsonable(getattr(span_data, "model_config", None) or {}),
            "usage": _jsonable(getattr(span_data, "usage", None) or {}),
        }
        return inputs, outputs, data
    # transcription / speech
    inputs = {"input": _jsonable(getattr(span_data, "input", None))}
    outputs = {"output": _jsonable(getattr(span_data, "output", None))}
    data = {
        "model": str(getattr(span_data, "model", None) or "unknown"),
        "parameters": _jsonable(getattr(span_data, "model_config", None) or {}),
    }
    return inputs, outputs, data


class SageOpenAIAgentsProcessor(_ProcessorBase):
    """``agents.tracing.TracingProcessor`` that records traces and spans into a ``SageRecorder``.

    Register with ``set_trace_processors([processor])`` (SAGE only) or
    ``add_trace_processor(processor)`` (alongside the default OpenAI exporter).
    One processor per recorder; it records every trace the SDK emits while registered.
    """

    def __init__(
        self,
        recorder: SageRecorder | None = None,
        *,
        trace_id: str | None = None,
        journal_dir: str | None = None,
        journal_durability: str | None = None,
    ) -> None:
        if not OPENAI_AGENTS_AVAILABLE:
            raise ImportError(INSTALL_HINT)
        self.recorder = recorder or SageRecorder(
            title="openai-agents",
            trace_id=trace_id,
            framework="openai-agents",
            journal_dir=journal_dir,
            journal_durability=journal_durability,
            register_trace=True,
        )
        self._lock = threading.Lock()
        self._traces: dict[str, str] = {}
        self._spans: dict[str, str] = {}
        self._unknown: list[tuple[str, str]] = []
        self._capture_errors: list[tuple[str, str]] = []
        self._capture_exceptions: list[BaseException] = []
        self._entered = False

    # -- context manager / lifecycle ------------------------------------------------------------

    def __enter__(self) -> "SageOpenAIAgentsProcessor":
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
            return sorted([*self._traces, *self._spans])

    def span_id_for(self, sdk_id: str) -> str | None:
        """SAGE span id for an SDK trace id or span id."""
        with self._lock:
            return self._spans.get(sdk_id) or self._traces.get(sdk_id)

    def assert_complete(self) -> None:
        """Raise ``CaptureIncompleteError`` unless every trace and span was closed cleanly."""
        with self._lock:
            open_ids = sorted([*self._traces, *self._spans])
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
        raise CaptureIncompleteError("OpenAI Agents capture incomplete: " + "; ".join(parts))

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

    # -- TracingProcessor --------------------------------------------------------------------------

    def on_trace_start(self, trace: Any) -> None:
        self._guard("on_trace_start", self._trace_start, trace)

    def on_trace_end(self, trace: Any) -> None:
        self._guard("on_trace_end", self._trace_end, trace)

    def on_span_start(self, span: Any) -> None:
        self._guard("on_span_start", self._span_start, span)

    def on_span_end(self, span: Any) -> None:
        self._guard("on_span_end", self._span_end, span)

    def shutdown(self) -> None:
        return None

    def force_flush(self) -> None:
        self.recorder.flush_journal()

    # -- mapping ---------------------------------------------------------------------------------

    def _trace_start(self, trace: Any) -> None:
        trace_id = str(trace.trace_id)
        attributes: dict[str, Any] = {"openai_agents.trace_id": trace_id}
        group_id = getattr(trace, "group_id", None)
        if group_id:
            attributes["openai_agents.group_id"] = str(group_id)
        metadata = getattr(trace, "metadata", None)
        if metadata:
            attributes["openai_agents.metadata"] = _jsonable(metadata)
        with self._lock:
            if trace_id in self._traces:
                self._capture_errors.append(("on_trace_start", "DuplicateTraceStart"))
                return
            span = self.recorder.start_span("chain", str(trace.name or "trace"), attributes=attributes)
            span.parent_id = None
            self._traces[trace_id] = span.span_id

    def _trace_end(self, trace: Any) -> None:
        trace_id = str(trace.trace_id)
        with self._lock:
            span_id = self._traces.pop(trace_id, None)
            if span_id is None:
                self._unknown.append(("on_trace_end", trace_id))
                return
            self.recorder.end_span(span_id)

    def _span_start(self, span: Any) -> None:
        span_data = span.span_data
        sdk_type = _sdk_type(span_data)
        if sdk_type == "custom":
            exported = getattr(span_data, "export", lambda: {})() or {}
            inner = (exported.get("data") or {}).get("sdk_span_type") if isinstance(exported, dict) else None
            sdk_type = str(inner or sdk_type)
        sage_type = SPAN_TYPE_MAP.get(sdk_type, "custom")
        key = str(span.span_id)
        attributes: dict[str, Any] = {
            "openai_agents.span_id": key,
            "openai_agents.trace_id": str(span.trace_id),
            "openai_agents.span_type": sdk_type,
        }
        if span.parent_id:
            attributes["openai_agents.parent_id"] = str(span.parent_id)
        inputs, data, agent_id = _start_payload(sdk_type, span_data)
        with self._lock:
            if key in self._spans:
                self._capture_errors.append(("on_span_start", "DuplicateSpanStart"))
                return
            parent = self._spans.get(str(span.parent_id)) if span.parent_id else None
            if parent is None:
                parent = self._traces.get(str(span.trace_id))
            sage_span = self.recorder.start_span(
                sage_type,
                _span_name(sdk_type, span_data),
                parent_id=parent,
                inputs=inputs,
                attributes=attributes,
                data=data,
                agent_id=agent_id,
            )
            # The recorder falls back to its implicit stack when parent_id is None.
            sage_span.parent_id = parent
            self._spans[key] = sage_span.span_id

    def _span_end(self, span: Any) -> None:
        key = str(span.span_id)
        span_data = span.span_data
        sdk_type = str(self._attr(key, "openai_agents.span_type") or _sdk_type(span_data))
        outputs: dict[str, Any] | None = None
        data: dict[str, Any] = {}
        status = "ok"
        error: Any = None

        if sdk_type in {"generation", "response", "transcription", "speech"}:
            inputs, outputs, data = _llm_end(sdk_type, span_data)
            self._set_inputs(key, inputs)
            data["input"], data["output"] = inputs, outputs
        elif sdk_type == "function":
            output = getattr(span_data, "output", None)
            outputs = {"output": _jsonable(output)}
            data = {"input": getattr(span_data, "input", None), "output": _jsonable(output)}
            mcp = getattr(span_data, "mcp_data", None)
            if mcp:
                data["mcp_data"] = _jsonable(mcp)
        elif sdk_type == "handoff":
            frm, to = getattr(span_data, "from_agent", None), getattr(span_data, "to_agent", None)
            data = {"from_agent": frm or "unknown", "to_agent": to or "unknown"}
        elif sdk_type == "guardrail":
            triggered = bool(getattr(span_data, "triggered", False))
            data = {"triggered": triggered, "decision": "block" if triggered else "allow"}
            if triggered:
                status = "error"
                error = {"type": "GuardrailTripwireTriggered", "message": f"guardrail {span_data.name} triggered"}
        elif sdk_type in {"task", "turn"}:
            exported = span_data.export() or {}
            data = {"sdk": _jsonable(exported.get("data") or {})}
        elif sdk_type == "mcp_tools":
            data = {"server": getattr(span_data, "server", None), "result": _jsonable(getattr(span_data, "result", None))}
        elif sdk_type == "custom":
            data = {"custom": _jsonable(getattr(span_data, "data", None))}
        elif sdk_type == "agent":
            data = {"tools": _jsonable(getattr(span_data, "tools", None)),
                    "handoffs": _jsonable(getattr(span_data, "handoffs", None))}

        sdk_error = span.error
        if sdk_error:
            status = "error"
            detail = sdk_error.get("data") or {}
            error = {
                "type": str(detail.get("name") or detail.get("type") or "Error") if isinstance(detail, dict) else "Error",
                "message": str(sdk_error.get("message") or ""),
            }
            if isinstance(detail, dict) and detail:
                data["error_data"] = _jsonable(detail)
        if sdk_type == "function":
            data["success"] = status == "ok"

        with self._lock:
            span_id = self._spans.pop(key, None)
            if span_id is None:
                self._unknown.append(("on_span_end", key))
                return
            self.recorder.end_span(span_id, status=status, outputs=outputs, error=error, data=data)

    def _attr(self, key: str, name: str) -> Any:
        with self._lock:
            span_id = self._spans.get(key)
        if span_id is None:
            return None
        return self.recorder._get_span(span_id).attributes.get(name)

    def _set_inputs(self, key: str, inputs: dict[str, Any]) -> None:
        with self._lock:
            span_id = self._spans.get(key)
        if span_id is not None:
            self.recorder._get_span(span_id).inputs = inputs


def attach_openai_agents_processor(
    *,
    trace_id: str | None = None,
    journal_dir: str | None = None,
    journal_durability: str | None = None,
    exclusive: bool = False,
) -> SageOpenAIAgentsProcessor:
    """Create a processor and register it with the SDK.

    ``exclusive=True`` replaces all processors (including the default OpenAI exporter);
    otherwise it is added next to them.
    """
    processor = SageOpenAIAgentsProcessor(
        trace_id=trace_id, journal_dir=journal_dir, journal_durability=journal_durability
    )
    from agents.tracing import add_trace_processor, set_trace_processors

    if exclusive:
        set_trace_processors([processor])
    else:
        add_trace_processor(processor)
    return processor
