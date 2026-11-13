"""LangChain callback adapter for SAGE.

Tested against ``langchain-core==1.8.0`` (see the ``langchain`` extra). Supported
path: sequential ``Runnable`` composition (``|``), chat models, text LLMs and tools,
via ``invoke``/``ainvoke`` with ``config={"callbacks": [handler]}``.

Callback failures surface (``raise_error = True``): a bug in capture fails the
workflow instead of silently dropping evidence. Restrict to development/staging
until production failure handling is agreed. Call ``assert_complete()`` before
handing off an artifact.

Not validated: parallel branches (``RunnableParallel``/``batch``), streaming token
events, retrievers, agent action events, retries, custom events, and LangGraph.
"""

from __future__ import annotations

import threading
from typing import Any
from uuid import UUID

from sage.errors import SageError
from sage.recorder import SageRecorder

try:  # Optional dependency: core SAGE must import without LangChain.
    from langchain_core.callbacks.base import AsyncCallbackHandler as _AsyncBaseHandler
    from langchain_core.callbacks.base import BaseCallbackHandler as _BaseHandler

    LANGCHAIN_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised via sys.modules simulation
    LANGCHAIN_AVAILABLE = False

    class _BaseHandler:  # type: ignore[no-redef]
        """Shim with the handler attributes LangChain inspects."""

        raise_error: bool = False
        run_inline: bool = False

    class _AsyncBaseHandler(_BaseHandler):  # type: ignore[no-redef]
        pass


_MAX_DEPTH = 8
_MAX_REPR = 200
_SAFE_PARAMS = ("model", "model_name", "temperature", "max_tokens", "top_p", "stop", "_type")
_ROLE_BY_TYPE = {"human": "user", "ai": "assistant", "system": "system", "tool": "tool"}


class CaptureIncompleteError(SageError):
    """LangChain capture is incomplete or hit an internal error; do not hand off."""


def _jsonable(value: Any, depth: int = 0) -> Any:
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if depth >= _MAX_DEPTH:
        return {"type": type(value).__name__, "truncated": True}
    if isinstance(value, BaseException):
        return {"type": type(value).__name__}
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _jsonable(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v, depth + 1) for v in value]
    if _is_message(value):
        return _message(value, depth)
    if hasattr(value, "page_content"):
        return {
            "page_content": _jsonable(getattr(value, "page_content", None), depth + 1),
            "metadata": _jsonable(getattr(value, "metadata", None) or {}, depth + 1),
        }
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        try:
            return _jsonable(dump(mode="json"), depth + 1)
        except Exception:
            pass
    try:
        text = repr(value)
    except Exception:
        text = "<unrepresentable>"
    return {"type": type(value).__name__, "repr": text[:_MAX_REPR]}


def _is_message(value: Any) -> bool:
    return hasattr(value, "content") and isinstance(getattr(value, "type", None), str)


def _message(value: Any, depth: int = 0) -> dict[str, Any]:
    msg_type = str(getattr(value, "type", "unknown"))
    out: dict[str, Any] = {
        "role": _ROLE_BY_TYPE.get(msg_type, msg_type),
        "content": _jsonable(getattr(value, "content", None), depth + 1),
    }
    tool_calls = getattr(value, "tool_calls", None)
    if tool_calls:
        out["tool_calls"] = _jsonable(tool_calls, depth + 1)
    for attr in ("name", "tool_call_id"):
        attr_value = getattr(value, attr, None)
        if isinstance(attr_value, str) and attr_value:
            out[attr] = attr_value
    return out


def _normalize_output(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return _jsonable(value)
    if _is_message(value):
        return _message(value)
    if hasattr(value, "generations") and not isinstance(value, (str, bytes)):
        return _llm_result(value)
    return {"output": _jsonable(value)}


def _llm_result(response: Any) -> dict[str, Any]:
    generations: list[list[dict[str, Any]]] = []
    for batch in getattr(response, "generations", None) or []:
        row: list[dict[str, Any]] = []
        for gen in batch or []:
            item: dict[str, Any] = {"text": _jsonable(getattr(gen, "text", ""))}
            message = getattr(gen, "message", None)
            if message is not None and _is_message(message):
                item["message"] = _message(message)
            row.append(item)
        generations.append(row)
    first = generations[0][0] if generations and generations[0] else {}
    out: dict[str, Any] = {"text": first.get("text", ""), "generations": generations}
    if "message" in first:
        out["message"] = first["message"]
    return out


def _usage(response: Any) -> dict[str, Any]:
    try:
        message = response.generations[0][0].message
    except Exception:
        message = None
    usage = getattr(message, "usage_metadata", None)
    if isinstance(usage, dict):
        return _jsonable(usage)
    llm_output = getattr(response, "llm_output", None)
    if isinstance(llm_output, dict) and isinstance(llm_output.get("token_usage"), dict):
        return _jsonable(llm_output["token_usage"])
    return {}


def _resolve_name(serialized: dict[str, Any] | None, kwargs: dict[str, Any], default: str) -> str:
    name = kwargs.get("name")
    if isinstance(name, str) and name:
        return name
    serialized = serialized if isinstance(serialized, dict) else {}
    name = serialized.get("name")
    if isinstance(name, str) and name:
        return name
    ident = serialized.get("id")
    if isinstance(ident, list) and ident:
        return str(ident[-1])
    if isinstance(ident, str) and ident:
        return ident
    return default


def _model_info(kwargs: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    params = kwargs.get("invocation_params")
    params = params if isinstance(params, dict) else {}
    metadata = kwargs.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    model = (
        params.get("model")
        or params.get("model_name")
        or metadata.get("ls_model_name")
        or params.get("_type")
        or "unknown"
    )
    safe = {k: _jsonable(params[k]) for k in _SAFE_PARAMS if k in params}
    return str(model), safe


class _SageLangChainCore:
    """Run-id keyed capture state shared by the sync and async handlers."""

    raise_error: bool = True
    run_inline: bool = True

    def __init__(
        self,
        recorder: SageRecorder | None = None,
        *,
        trace_id: str | None = None,
        journal_dir: str | None = None,
        journal_durability: str | None = None,
    ) -> None:
        self.recorder = recorder or SageRecorder(
            title="langchain",
            trace_id=trace_id,
            framework="langchain",
            journal_dir=journal_dir,
            journal_durability=journal_durability,
            register_trace=True,
        )
        self._lock = threading.Lock()
        self._run_spans: dict[str, str] = {}
        self._unknown_runs: list[tuple[str, str]] = []
        self._capture_errors: list[tuple[str, str]] = []
        self._capture_exceptions: list[BaseException] = []
        self._entered = False

    @property
    def ignore_llm(self) -> bool:
        return False

    @property
    def ignore_chain(self) -> bool:
        return False

    @property
    def ignore_chat_model(self) -> bool:
        return False

    @property
    def ignore_agent(self) -> bool:
        # langchain-core gates on_tool_start/end/error on ignore_agent.
        return False

    @property
    def ignore_retriever(self) -> bool:
        return True

    @property
    def ignore_retry(self) -> bool:
        return True

    @property
    def ignore_custom_event(self) -> bool:
        return True

    def __enter__(self):
        self.recorder.__enter__()
        self._entered = True
        return self

    def __exit__(self, *args: Any) -> None:
        if self._entered:
            self.recorder.__exit__(*args)
            self._entered = False

    @property
    def open_runs(self) -> list[str]:
        with self._lock:
            return sorted(self._run_spans)

    def span_id_for_run(self, run_id: UUID | str) -> str | None:
        with self._lock:
            return self._run_spans.get(str(run_id))

    def assert_complete(self) -> None:
        """Raise ``CaptureIncompleteError`` unless every observed run was closed cleanly.

        Workflow exceptions reported through ``on_*_error`` count as closed runs.
        The message holds only counts, run ids and exception class names.
        """
        with self._lock:
            open_runs = sorted(self._run_spans)
            unknown = list(self._unknown_runs)
            errors = list(self._capture_errors)
        if not (open_runs or unknown or errors):
            return
        parts = []
        if open_runs:
            parts.append(f"open_runs={len(open_runs)} {open_runs}")
        if unknown:
            parts.append(
                f"unknown_run_events={len(unknown)} "
                f"{[f'{event}:{run}' for event, run in unknown]}"
            )
        if errors:
            parts.append(
                f"capture_errors={len(errors)} {[f'{event}:{kind}' for event, kind in errors]}"
            )
        raise CaptureIncompleteError("LangChain capture incomplete: " + "; ".join(parts))

    def _guard(self, event: str, fn: Any, *args: Any) -> None:
        try:
            fn(*args)
        except Exception as exc:
            with self._lock:
                self._capture_errors.append((event, type(exc).__name__))
                self._capture_exceptions.append(exc)
            if self.raise_error:
                raise CaptureIncompleteError(
                    f"SAGE capture failed in {event}: {type(exc).__name__}"
                ) from None

    def _start(
        self,
        event: str,
        span_type: str,
        name: str,
        kwargs: dict[str, Any],
        *,
        inputs: dict[str, Any],
        data: dict[str, Any] | None = None,
    ) -> None:
        run_id = kwargs.get("run_id")
        if run_id is None:
            raise ValueError("callback is missing run_id")
        key = str(run_id)
        parent_key = kwargs.get("parent_run_id")
        attributes: dict[str, Any] = {"langchain.run_id": key}
        if parent_key is not None:
            attributes["langchain.parent_run_id"] = str(parent_key)
        tags = kwargs.get("tags")
        if tags:
            attributes["langchain.tags"] = [str(t) for t in tags]
        with self._lock:
            if key in self._run_spans:
                self._capture_errors.append((event, "DuplicateRunStart"))
                return
            parent_span = self._run_spans.get(str(parent_key)) if parent_key is not None else None
            span = self.recorder.start_span(
                span_type,
                name,
                parent_id=parent_span,
                inputs=inputs,
                attributes=attributes,
                data=data,
            )
            # The recorder falls back to its implicit stack when parent_id is None;
            # LangChain run ids are the only source of parentage here.
            span.parent_id = parent_span
            self._run_spans[key] = span.span_id

    def _finish(
        self,
        event: str,
        kwargs: dict[str, Any],
        *,
        outputs: dict[str, Any] | None = None,
        error: BaseException | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        key = str(kwargs.get("run_id"))
        with self._lock:
            span_id = self._run_spans.pop(key, None)
            if span_id is None:
                self._unknown_runs.append((event, key))
                return
            if error is not None:
                self.recorder.end_span(span_id, status="error", error=error, data=data)
            else:
                self.recorder.end_span(span_id, outputs=outputs, data=data)

    def _chain_start(self, serialized: Any, inputs: Any, kwargs: dict[str, Any]) -> None:
        self._start(
            "on_chain_start",
            "chain",
            _resolve_name(serialized, kwargs, "chain"),
            kwargs,
            inputs=_normalize_output(inputs) if isinstance(inputs, dict) else {"input": _jsonable(inputs)},
        )

    def _chain_end(self, outputs: Any, kwargs: dict[str, Any]) -> None:
        self._finish("on_chain_end", kwargs, outputs=_normalize_output(outputs))

    def _chat_model_start(self, serialized: Any, messages: Any, kwargs: dict[str, Any]) -> None:
        model, params = _model_info(kwargs)
        batches = [[_jsonable(m) for m in (batch or [])] for batch in (messages or [])]
        self._start(
            "on_chat_model_start",
            "llm",
            _resolve_name(serialized, kwargs, "chat_model"),
            kwargs,
            inputs={"messages": batches},
            data={"model": model, "parameters": params},
        )

    def _llm_start(self, serialized: Any, prompts: Any, kwargs: dict[str, Any]) -> None:
        model, params = _model_info(kwargs)
        self._start(
            "on_llm_start",
            "llm",
            _resolve_name(serialized, kwargs, "llm"),
            kwargs,
            inputs={"prompts": [_jsonable(p) for p in (prompts or [])]},
            data={"model": model, "parameters": params},
        )

    def _llm_end(self, response: Any, kwargs: dict[str, Any]) -> None:
        outputs = _normalize_output(response)
        usage = _usage(response)
        self._finish("on_llm_end", kwargs, outputs=outputs, data={"usage": usage} if usage else None)

    def _tool_start(self, serialized: Any, input_str: Any, kwargs: dict[str, Any]) -> None:
        inputs: dict[str, Any] = {"input": _jsonable(input_str)}
        if isinstance(kwargs.get("inputs"), dict):
            inputs["inputs"] = _jsonable(kwargs["inputs"])
        name = _resolve_name(serialized, kwargs, "tool")
        self._start("on_tool_start", "tool", name, kwargs, inputs=inputs, data={"tool_name": name})

    def _tool_end(self, output: Any, kwargs: dict[str, Any]) -> None:
        self._finish("on_tool_end", kwargs, outputs=_normalize_output(output), data={"success": True})

    def _error(self, event: str, error: BaseException, kwargs: dict[str, Any]) -> None:
        data = {"success": False} if event == "on_tool_error" else None
        self._finish(event, kwargs, error=error, data=data)


class SageLangChainCallback(_SageLangChainCore, _BaseHandler):
    """LangChain callback handler that records chain, model and tool runs as SAGE spans.

    Pass via ``config={"callbacks": [handler]}``. Works for ``invoke`` and ``ainvoke``
    (``run_inline`` keeps sync callbacks ordered on the event loop). One handler
    instance per workflow run; separate runs need separate handlers.
    """

    def on_chain_start(self, serialized: dict[str, Any], inputs: dict[str, Any], **kwargs: Any) -> None:
        self._guard("on_chain_start", self._chain_start, serialized, inputs, kwargs)

    def on_chain_end(self, outputs: dict[str, Any], **kwargs: Any) -> None:
        self._guard("on_chain_end", self._chain_end, outputs, kwargs)

    def on_chain_error(self, error: BaseException, **kwargs: Any) -> None:
        self._guard("on_chain_error", self._error, "on_chain_error", error, kwargs)

    def on_chat_model_start(self, serialized: dict[str, Any], messages: list[list[Any]], **kwargs: Any) -> None:
        self._guard("on_chat_model_start", self._chat_model_start, serialized, messages, kwargs)

    def on_llm_start(self, serialized: dict[str, Any], prompts: list[str], **kwargs: Any) -> None:
        self._guard("on_llm_start", self._llm_start, serialized, prompts, kwargs)

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        self._guard("on_llm_end", self._llm_end, response, kwargs)

    def on_llm_error(self, error: BaseException, **kwargs: Any) -> None:
        self._guard("on_llm_error", self._error, "on_llm_error", error, kwargs)

    def on_tool_start(self, serialized: dict[str, Any], input_str: str, **kwargs: Any) -> None:
        self._guard("on_tool_start", self._tool_start, serialized, input_str, kwargs)

    def on_tool_end(self, output: Any, **kwargs: Any) -> None:
        self._guard("on_tool_end", self._tool_end, output, kwargs)

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        self._guard("on_tool_error", self._error, "on_tool_error", error, kwargs)


class AsyncSageLangChainCallback(_SageLangChainCore, _AsyncBaseHandler):
    """Async variant of :class:`SageLangChainCallback` for ``ainvoke`` call paths.

    Under a sync ``invoke``, LangChain swallows exceptions raised by async
    handlers; capture failures are still reported by ``assert_complete()``.
    """

    async def on_chain_start(self, serialized: dict[str, Any], inputs: dict[str, Any], **kwargs: Any) -> None:
        self._guard("on_chain_start", self._chain_start, serialized, inputs, kwargs)

    async def on_chain_end(self, outputs: dict[str, Any], **kwargs: Any) -> None:
        self._guard("on_chain_end", self._chain_end, outputs, kwargs)

    async def on_chain_error(self, error: BaseException, **kwargs: Any) -> None:
        self._guard("on_chain_error", self._error, "on_chain_error", error, kwargs)

    async def on_chat_model_start(
        self, serialized: dict[str, Any], messages: list[list[Any]], **kwargs: Any
    ) -> None:
        self._guard("on_chat_model_start", self._chat_model_start, serialized, messages, kwargs)

    async def on_llm_start(self, serialized: dict[str, Any], prompts: list[str], **kwargs: Any) -> None:
        self._guard("on_llm_start", self._llm_start, serialized, prompts, kwargs)

    async def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        self._guard("on_llm_end", self._llm_end, response, kwargs)

    async def on_llm_error(self, error: BaseException, **kwargs: Any) -> None:
        self._guard("on_llm_error", self._error, "on_llm_error", error, kwargs)

    async def on_tool_start(self, serialized: dict[str, Any], input_str: str, **kwargs: Any) -> None:
        self._guard("on_tool_start", self._tool_start, serialized, input_str, kwargs)

    async def on_tool_end(self, output: Any, **kwargs: Any) -> None:
        self._guard("on_tool_end", self._tool_end, output, kwargs)

    async def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        self._guard("on_tool_error", self._error, "on_tool_error", error, kwargs)


def attach_langchain_callback(
    *,
    trace_id: str | None = None,
    journal_dir: str | None = None,
    journal_durability: str | None = None,
) -> SageLangChainCallback:
    return SageLangChainCallback(
        trace_id=trace_id, journal_dir=journal_dir, journal_durability=journal_durability
    )
