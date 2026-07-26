from __future__ import annotations

from typing import Any
from uuid import UUID

from sage.recorder import SageRecorder


class SageLangChainCallback:
    """Thin LangChain-compatible callback sink (no LangChain dependency required).

    Pass into LangChain via ``callbacks=[handler]`` when langchain is installed.
    Methods mirror the BaseCallbackHandler surface used by LLM/tool/chain events.
    """

    def __init__(
        self,
        recorder: SageRecorder | None = None,
        *,
        trace_id: str | None = None,
        journal_dir: str | None = None,
    ) -> None:
        self.recorder = recorder or SageRecorder(
            title="langchain",
            trace_id=trace_id,
            framework="langchain",
            journal_dir=journal_dir,
            register_trace=True,
        )
        self._run_spans: dict[str, str] = {}
        self._entered = False

    def __enter__(self) -> "SageLangChainCallback":
        self.recorder.__enter__()
        self._entered = True
        return self

    def __exit__(self, *args: Any) -> None:
        if self._entered:
            self.recorder.__exit__(*args)
            self._entered = False

    def _key(self, run_id: UUID | str | None) -> str:
        return str(run_id or "unknown")

    def on_chain_start(self, serialized: dict[str, Any], inputs: dict[str, Any], **kwargs: Any) -> None:
        name = serialized.get("name") or serialized.get("id") or "chain"
        if isinstance(name, list):
            name = ".".join(str(x) for x in name)
        span = self.recorder.start_span("chain", str(name), inputs=dict(inputs or {}))
        self._run_spans[self._key(kwargs.get("run_id"))] = span.span_id

    def on_chain_end(self, outputs: dict[str, Any], **kwargs: Any) -> None:
        span_id = self._run_spans.pop(self._key(kwargs.get("run_id")), None)
        if span_id:
            self.recorder.end_span(span_id, outputs=dict(outputs or {}))

    def on_chain_error(self, error: BaseException, **kwargs: Any) -> None:
        span_id = self._run_spans.pop(self._key(kwargs.get("run_id")), None)
        if span_id:
            self.recorder.end_span(span_id, status="error", error=error)

    def on_llm_start(self, serialized: dict[str, Any], prompts: list[str], **kwargs: Any) -> None:
        name = serialized.get("name") or "llm"
        span = self.recorder.start_span(
            "llm",
            str(name),
            inputs={"prompts": list(prompts or [])},
            data={"model": (kwargs.get("invocation_params") or {}).get("model", "unknown")},
        )
        self._run_spans[self._key(kwargs.get("run_id"))] = span.span_id

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        span_id = self._run_spans.pop(self._key(kwargs.get("run_id")), None)
        if not span_id:
            return
        generations = getattr(response, "generations", None)
        text = ""
        if generations:
            try:
                text = generations[0][0].text
            except Exception:
                text = str(response)
        else:
            text = str(response)
        self.recorder.end_span(span_id, outputs={"text": text})

    def on_llm_error(self, error: BaseException, **kwargs: Any) -> None:
        span_id = self._run_spans.pop(self._key(kwargs.get("run_id")), None)
        if span_id:
            self.recorder.end_span(span_id, status="error", error=error)

    def on_tool_start(self, serialized: dict[str, Any], input_str: str, **kwargs: Any) -> None:
        name = serialized.get("name") or "tool"
        span = self.recorder.start_span("tool", str(name), inputs={"input": input_str})
        self._run_spans[self._key(kwargs.get("run_id"))] = span.span_id

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        span_id = self._run_spans.pop(self._key(kwargs.get("run_id")), None)
        if span_id:
            self.recorder.end_span(span_id, outputs={"output": output})

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        span_id = self._run_spans.pop(self._key(kwargs.get("run_id")), None)
        if span_id:
            self.recorder.end_span(span_id, status="error", error=error)


def attach_langchain_callback(
    *,
    trace_id: str | None = None,
    journal_dir: str | None = None,
) -> SageLangChainCallback:
    return SageLangChainCallback(trace_id=trace_id, journal_dir=journal_dir)
