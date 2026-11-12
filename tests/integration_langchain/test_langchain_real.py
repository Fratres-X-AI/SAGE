"""Integration tests against real langchain-core objects (pinned in the ``langchain`` extra)."""

from __future__ import annotations

import asyncio
import threading
from typing import Any
from uuid import uuid4

import pytest

pytest.importorskip("langchain_core")

from langchain_core.callbacks import BaseCallbackHandler, CallbackManager
from langchain_core.callbacks.base import AsyncCallbackHandler
from langchain_core.language_models.fake_chat_models import FakeListChatModel
from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableLambda
from langchain_core.tools import tool

from sage.adapters.langchain_callback import (
    AsyncSageLangChainCallback,
    CaptureIncompleteError,
    SageLangChainCallback,
)
from sage.bundle_io import load_bundle


@pytest.fixture(autouse=True)
def _no_external_tracing(monkeypatch):
    monkeypatch.setenv("LANGCHAIN_TRACING_V2", "false")
    monkeypatch.setenv("LANGSMITH_TRACING", "false")
    for name in ("LANGCHAIN_API_KEY", "LANGSMITH_API_KEY", "LANGCHAIN_ENDPOINT", "LANGSMITH_ENDPOINT"):
        monkeypatch.delenv(name, raising=False)


@tool
def lookup(query: str) -> str:
    """Look up an order status."""
    return f"order {query}: shipped"


@tool
def broken_lookup(query: str) -> str:
    """Lookup backend that is down."""
    raise ValueError(f"backend unavailable for {query}")


class ExplodingChatModel(FakeListChatModel):
    def _call(self, *args: Any, **kwargs: Any) -> str:
        raise RuntimeError("model provider timeout")


def _to_query(payload: dict) -> str:
    return payload["order_id"]


def _to_prompt(tool_output: str) -> str:
    return f"Summarize: {tool_output}"


def _content(message: AIMessage) -> str:
    return message.content


def _workflow(responses: list[str] | None = None, *, tool_obj=lookup, model=None):
    model = model or FakeListChatModel(responses=responses or ["The order shipped."])
    return (
        RunnableLambda(_to_query, name="to_query")
        | tool_obj
        | RunnableLambda(_to_prompt, name="to_prompt")
        | model
        | RunnableLambda(_content, name="content")
    )


def _spans(handler):
    return list(handler.recorder.bundle.spans)


def _by_name(handler, name):
    matches = [s for s in _spans(handler) if s.name == name]
    assert len(matches) == 1, [s.name for s in _spans(handler)]
    return matches[0]


def _root(handler):
    roots = [s for s in _spans(handler) if s.parent_id is None]
    assert len(roots) == 1, [(s.name, s.parent_id) for s in _spans(handler)]
    return roots[0]


def _export_and_load(handler, tmp_path, name="lc.sage.json"):
    path = handler.recorder.export(tmp_path / name)
    return load_bundle(path, verify=True)


def test_handler_contract_matches_framework():
    handler = SageLangChainCallback(trace_id="lc-contract")
    assert isinstance(handler, BaseCallbackHandler)
    assert handler.raise_error is True
    assert handler.run_inline is True
    for attr in ("ignore_llm", "ignore_chain", "ignore_chat_model", "ignore_agent"):
        assert getattr(handler, attr) is False
    for attr in ("ignore_retriever", "ignore_retry", "ignore_custom_event"):
        assert getattr(handler, attr) is True
    assert isinstance(AsyncSageLangChainCallback(trace_id="lc-contract-async"), AsyncCallbackHandler)


def test_successful_sequential_workflow_matches_baseline(tmp_path):
    baseline = _workflow().invoke({"order_id": "A-1"})
    handler = SageLangChainCallback(trace_id="lc-seq")
    with handler:
        result = _workflow().invoke({"order_id": "A-1"}, config={"callbacks": [handler]})
    assert result == baseline == "The order shipped."
    handler.assert_complete()

    root = _root(handler)
    assert root.type == "chain"
    assert root.outputs == {"output": "The order shipped."}
    llm = next(s for s in _spans(handler) if s.type == "llm")
    tool_span = _by_name(handler, "lookup")
    assert tool_span.type == "tool"
    assert llm.parent_id == root.span_id
    assert tool_span.parent_id == root.span_id
    assert tool_span.outputs == {"output": "order A-1: shipped"}
    assert llm.inputs["messages"] == [[{"role": "user", "content": "Summarize: order A-1: shipped"}]]
    assert llm.outputs["text"] == "The order shipped."
    assert llm.outputs["message"]["role"] == "assistant"
    assert all(s.status == "ok" for s in _spans(handler))

    loaded = _export_and_load(handler, tmp_path)
    assert loaded.status == "completed"
    assert {s.type for s in loaded.spans} >= {"chain", "llm", "tool"}


def test_tool_exception_is_raised_and_recorded(tmp_path):
    handler = SageLangChainCallback(trace_id="lc-tool-err")
    with pytest.raises(ValueError, match="backend unavailable"):
        with handler:
            _workflow(tool_obj=broken_lookup).invoke({"order_id": "B-2"}, config={"callbacks": [handler]})
    handler.assert_complete()

    tool_span = _by_name(handler, "broken_lookup")
    assert tool_span.status == "error"
    assert tool_span.error is not None and tool_span.error.type == "ValueError"
    assert tool_span.data["success"] is False
    assert _root(handler).status == "error"
    assert not any(s.type == "llm" for s in _spans(handler))

    loaded = _export_and_load(handler, tmp_path)
    assert loaded.status == "failed"


def test_model_exception_is_raised_and_recorded(tmp_path):
    handler = SageLangChainCallback(trace_id="lc-model-err")
    model = ExplodingChatModel(responses=["unused"])
    with pytest.raises(RuntimeError, match="model provider timeout"):
        with handler:
            _workflow(model=model).invoke({"order_id": "C-3"}, config={"callbacks": [handler]})
    handler.assert_complete()

    llm = next(s for s in _spans(handler) if s.type == "llm")
    assert llm.status == "error"
    assert llm.error is not None and llm.error.type == "RuntimeError"
    assert llm.parent_id == _root(handler).span_id
    assert _by_name(handler, "lookup").status == "ok"
    _export_and_load(handler, tmp_path)


@pytest.mark.parametrize("handler_cls", [SageLangChainCallback, AsyncSageLangChainCallback])
def test_async_sequential_workflow(tmp_path, handler_cls):
    baseline = asyncio.run(_workflow().ainvoke({"order_id": "D-4"}))
    handler = handler_cls(trace_id=f"lc-async-{handler_cls.__name__}")

    async def run():
        with handler:
            return await _workflow().ainvoke({"order_id": "D-4"}, config={"callbacks": [handler]})

    assert asyncio.run(run()) == baseline
    handler.assert_complete()
    root = _root(handler)
    assert {s.type for s in _spans(handler)} == {"chain", "llm", "tool"}
    for span in _spans(handler):
        if span is not root:
            assert span.parent_id == root.span_id
    _export_and_load(handler, tmp_path)


def test_nested_parent_child_spans():
    # A bare ``seq | seq`` is flattened by LangChain; the binding keeps a real nested run.
    inner = (RunnableLambda(_to_query, name="inner_query") | lookup).with_config(run_name="inner_chain")
    outer = (
        RunnableLambda(lambda d: d, name="passthrough")
        | inner
        | RunnableLambda(_to_prompt, name="to_prompt")
        | FakeListChatModel(responses=["ok"])
    )
    handler = SageLangChainCallback(trace_id="lc-nested")
    with handler:
        outer.invoke({"order_id": "E-5"}, config={"callbacks": [handler]})
    handler.assert_complete()

    by_id = {s.span_id: s for s in _spans(handler)}
    root = _root(handler)
    tool_span = _by_name(handler, "lookup")
    inner_chain = by_id[tool_span.parent_id]
    assert inner_chain.name == "inner_chain"
    assert inner_chain.type == "chain" and inner_chain.parent_id == root.span_id
    assert _by_name(handler, "inner_query").parent_id == inner_chain.span_id
    llm = next(s for s in _spans(handler) if s.type == "llm")
    assert llm.parent_id == root.span_id
    for span in _spans(handler):
        assert span.attributes["langchain.run_id"]
        if span.parent_id is not None:
            parent = by_id[span.parent_id]
            assert span.attributes["langchain.parent_run_id"] == parent.attributes["langchain.run_id"]


def test_concurrent_runs_with_separate_handlers_do_not_mix(tmp_path):
    handlers = {key: SageLangChainCallback(trace_id=f"lc-thread-{key}") for key in ("alpha", "beta")}
    results: dict[str, Any] = {}
    barrier = threading.Barrier(2)

    def slow_query(payload: dict) -> str:
        barrier.wait(timeout=10)
        return payload["order_id"]

    def worker(key: str) -> None:
        chain = (
            RunnableLambda(slow_query, name="slow_query")
            | lookup
            | RunnableLambda(_to_prompt, name="to_prompt")
            | FakeListChatModel(responses=[f"reply-{key}"])
            | RunnableLambda(_content, name="content")
        )
        handler = handlers[key]
        try:
            with handler:
                results[key] = chain.invoke({"order_id": f"order-{key}"}, config={"callbacks": [handler]})
        except BaseException as exc:  # surfaced through results for the main thread
            results[key] = exc

    threads = [threading.Thread(target=worker, args=(key,)) for key in handlers]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    for key, other in (("alpha", "beta"), ("beta", "alpha")):
        assert results[key] == f"reply-{key}"
        handler = handlers[key]
        handler.assert_complete()
        spans = _spans(handler)
        assert len(spans) == 6
        assert {s.trace_id for s in spans} == {handler.recorder.bundle.bundle_id}
        dump = repr([(s.inputs, s.outputs) for s in spans])
        assert f"order-{key}" in dump and f"order-{other}" not in dump
        ids = {s.span_id for s in spans}
        assert all(s.parent_id is None or s.parent_id in ids for s in spans)
        _export_and_load(handler, tmp_path, name=f"{key}.sage.json")


def test_missing_serialized_metadata_via_callback_manager(tmp_path):
    handler = SageLangChainCallback(trace_id="lc-noserial")
    with handler:
        manager = CallbackManager(handlers=[handler], inheritable_handlers=[handler])
        chain_run = manager.on_chain_start(None, {"question": "status?"})
        tool_run = chain_run.get_child().on_tool_start(None, "Q-1")
        tool_run.on_tool_end("done")
        model_runs = chain_run.get_child().on_chat_model_start(None, [[AIMessage(content="hi")]])
        for run in model_runs:
            run.on_llm_end(FakeListChatModel(responses=["x"]).generate([[AIMessage(content="y")]]))
        chain_run.on_chain_end({"answer": "done"})
    handler.assert_complete()

    root = _by_name(handler, "chain")
    assert root.parent_id is None
    assert root.inputs == {"question": "status?"}
    assert root.outputs == {"answer": "done"}
    assert _by_name(handler, "tool").parent_id == root.span_id
    assert _by_name(handler, "chat_model").parent_id == root.span_id
    _export_and_load(handler, tmp_path)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (42, {"output": 42}),
        (3.5, {"output": 3.5}),
        (True, {"output": True}),
        (None, {"output": None}),
        ("text", {"output": "text"}),
        ([1, "two", {"three": 3}], {"output": [1, "two", {"three": 3}]}),
        ({"answer": 1, "nested": {"k": [1, 2]}}, {"answer": 1, "nested": {"k": [1, 2]}}),
        (AIMessage(content="hello"), {"role": "assistant", "content": "hello"}),
    ],
)
def test_scalar_and_structured_outputs(value, expected):
    handler = SageLangChainCallback(trace_id=f"lc-out-{uuid4().hex[:8]}")
    with handler:
        result = RunnableLambda(lambda _: value, name="emit").invoke({"x": 1}, config={"callbacks": [handler]})
    assert result == value
    handler.assert_complete()
    assert _by_name(handler, "emit").outputs == expected


def test_unknown_output_object_does_not_crash():
    class Opaque:
        def __repr__(self) -> str:
            return "Opaque()"

    handler = SageLangChainCallback(trace_id="lc-opaque")
    with handler:
        RunnableLambda(lambda _: Opaque(), name="emit").invoke({}, config={"callbacks": [handler]})
    handler.assert_complete()
    assert _by_name(handler, "emit").outputs == {"output": {"type": "Opaque", "repr": "Opaque()"}}


def test_incomplete_capture_open_run_fails_assert_complete():
    handler = SageLangChainCallback(trace_id="lc-open")
    run_id = uuid4()
    handler.on_chain_start(None, {"secret_payload": "canary-open-123"}, run_id=run_id)
    with pytest.raises(CaptureIncompleteError) as info:
        handler.assert_complete()
    message = str(info.value)
    assert str(run_id) in message and "open_runs=1" in message
    assert "canary-open-123" not in message


def test_end_for_unknown_run_fails_assert_complete():
    handler = SageLangChainCallback(trace_id="lc-unknown")
    run_id = uuid4()
    handler.on_chain_end({"secret_payload": "canary-unknown-456"}, run_id=run_id)
    with pytest.raises(CaptureIncompleteError) as info:
        handler.assert_complete()
    message = str(info.value)
    assert f"on_chain_end:{run_id}" in message
    assert "canary-unknown-456" not in message


def test_capture_error_surfaces_and_is_sanitized(monkeypatch):
    handler = SageLangChainCallback(trace_id="lc-capture-err")

    def broken_start_span(*args: Any, **kwargs: Any):
        raise RuntimeError("leaked canary-capture-789")

    monkeypatch.setattr(handler.recorder, "start_span", broken_start_span)
    with pytest.raises(CaptureIncompleteError) as raised:
        _workflow().invoke({"order_id": "F-6"}, config={"callbacks": [handler]})
    assert "canary-capture-789" not in str(raised.value)
    assert "RuntimeError" in str(raised.value)

    with pytest.raises(CaptureIncompleteError) as info:
        handler.assert_complete()
    message = str(info.value)
    assert "capture_errors=1" in message and "on_chain_start:RuntimeError" in message
    assert "canary-capture-789" not in message


def test_workflow_exception_is_not_incomplete_capture():
    handler = SageLangChainCallback(trace_id="lc-wf-err")

    def fail(_: Any) -> None:
        raise KeyError("business rule")

    with pytest.raises(KeyError):
        RunnableLambda(fail, name="fail").invoke({}, config={"callbacks": [handler]})
    handler.assert_complete()
    assert _by_name(handler, "fail").status == "error"
