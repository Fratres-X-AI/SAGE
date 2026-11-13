"""Integration tests against a real LangGraph ``StateGraph`` (pinned in the ``langgraph`` extra)."""

from __future__ import annotations

import asyncio
import operator
from typing import Annotated, Any, TypedDict

import pytest

pytest.importorskip("langgraph")

from langchain_core.language_models.fake_chat_models import FakeListChatModel
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.tools import tool
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.types import Command, interrupt

from sage.adapters.langchain_callback import AsyncSageLangChainCallback, SageLangChainCallback
from sage.bundle_io import load_bundle


@pytest.fixture(autouse=True)
def _no_external_tracing(monkeypatch):
    monkeypatch.setenv("LANGCHAIN_TRACING_V2", "false")
    monkeypatch.setenv("LANGSMITH_TRACING", "false")
    for name in ("LANGCHAIN_API_KEY", "LANGSMITH_API_KEY", "LANGCHAIN_ENDPOINT", "LANGSMITH_ENDPOINT"):
        monkeypatch.delenv(name, raising=False)


class State(TypedDict):
    x: int
    log: Annotated[list, operator.add]


def _spans(handler):
    return list(handler.recorder.bundle.spans)


def _nodes(handler, node):
    return [s for s in _spans(handler) if s.attributes.get("langgraph.node") == node
            and s.parent_id is not None and _by_id(handler)[s.parent_id].name == "LangGraph"]


def _by_id(handler):
    return {s.span_id: s for s in _spans(handler)}


def _roots(handler):
    return [s for s in _spans(handler) if s.parent_id is None]


def _assert_parent_links_match_run_ids(handler):
    by_id = _by_id(handler)
    for span in _spans(handler):
        assert span.attributes["langchain.run_id"]
        if span.parent_id is None:
            assert "langchain.parent_run_id" not in span.attributes
        else:
            assert span.attributes["langchain.parent_run_id"] == by_id[span.parent_id].attributes["langchain.run_id"]


def _export_and_load(handler, tmp_path, name="lg.sage.json"):
    return load_bundle(handler.recorder.export(tmp_path / name), verify=True)


def _linear_graph():
    g = StateGraph(State)
    g.add_node("one", lambda s: {"x": s["x"] + 1, "log": ["one"]})
    g.add_node("two", lambda s: {"x": s["x"] * 2, "log": ["two"]})
    g.add_edge(START, "one")
    g.add_conditional_edges("one", lambda s: "two" if s["x"] < 5 else END)
    g.add_edge("two", END)
    return g.compile()


def test_linear_graph_with_conditional_edge(tmp_path):
    baseline = _linear_graph().invoke({"x": 1, "log": []})
    handler = SageLangChainCallback(trace_id="lg-linear")
    with handler:
        result = _linear_graph().invoke({"x": 1, "log": []}, config={"callbacks": [handler]})
    assert result == baseline == {"x": 4, "log": ["one", "two"]}
    handler.assert_complete()

    [root] = _roots(handler)
    assert root.name == "LangGraph" and root.outputs == {"x": 4, "log": ["one", "two"]}
    [one] = _nodes(handler, "one")
    [two] = _nodes(handler, "two")
    assert one.attributes["langgraph.step"] == 1 and two.attributes["langgraph.step"] == 2
    assert one.outputs == {"x": 2, "log": ["one"]}
    _assert_parent_links_match_run_ids(handler)
    assert _export_and_load(handler, tmp_path).status == "completed"


def test_conditional_edge_skips_node():
    handler = SageLangChainCallback(trace_id="lg-skip")
    with handler:
        result = _linear_graph().invoke({"x": 7, "log": []}, config={"callbacks": [handler]})
    assert result == {"x": 8, "log": ["one"]}
    handler.assert_complete()
    assert _nodes(handler, "two") == []


@tool
def order_status(order_id: str) -> str:
    """Look up an order."""
    return f"order {order_id}: shipped"


def _tool_graph():
    model = FakeListChatModel(responses=["The order shipped."])

    def call_tool(state):
        return {"messages": [AIMessage(content="", tool_calls=[
            {"name": "order_status", "args": {"order_id": "A-1"}, "id": "call-1", "type": "tool_call"}])]}

    def answer(state):
        return {"messages": [model.invoke(state["messages"])]}

    class Msgs(TypedDict):
        messages: Annotated[list, operator.add]

    g = StateGraph(Msgs)
    g.add_node("plan", call_tool)
    g.add_node("tools", ToolNode([order_status]))
    g.add_node("answer", answer)
    g.add_edge(START, "plan")
    g.add_edge("plan", "tools")
    g.add_edge("tools", "answer")
    g.add_edge("answer", END)
    return g.compile()


def test_tool_node_and_model_inside_graph(tmp_path):
    handler = SageLangChainCallback(trace_id="lg-tool")
    with handler:
        result = _tool_graph().invoke({"messages": [HumanMessage(content="where is A-1?")]},
                                      config={"callbacks": [handler]})
    assert result["messages"][-1].content == "The order shipped."
    handler.assert_complete()

    by_id = _by_id(handler)
    [tool_span] = [s for s in _spans(handler) if s.type == "tool"]
    assert tool_span.name == "order_status" and tool_span.status == "ok"
    assert "order A-1: shipped" in repr(tool_span.outputs)
    ancestors = []
    cur = tool_span
    while cur.parent_id:
        cur = by_id[cur.parent_id]
        ancestors.append(cur.attributes.get("langgraph.node"))
    assert "tools" in ancestors
    [llm] = [s for s in _spans(handler) if s.type == "llm"]
    assert llm.attributes["langgraph.node"] == "answer"
    _assert_parent_links_match_run_ids(handler)
    _export_and_load(handler, tmp_path)


def test_fan_out_fan_in_parallel_branches(tmp_path):
    g = StateGraph(State)
    g.add_node("a", lambda s: {"log": ["a"]})
    g.add_node("b", lambda s: {"log": ["b"]})
    g.add_node("join", lambda s: {"x": len(s["log"])})
    g.add_edge(START, "a")
    g.add_edge(START, "b")
    g.add_edge(["a", "b"], "join")
    g.add_edge("join", END)
    handler = SageLangChainCallback(trace_id="lg-fan")
    with handler:
        result = g.compile().invoke({"x": 0, "log": []}, config={"callbacks": [handler]})
    assert result["x"] == 2 and sorted(result["log"]) == ["a", "b"]
    handler.assert_complete()

    [root] = _roots(handler)
    [a], [b], [join] = _nodes(handler, "a"), _nodes(handler, "b"), _nodes(handler, "join")
    assert a.parent_id == b.parent_id == join.parent_id == root.span_id
    assert a.attributes["langgraph.step"] == b.attributes["langgraph.step"] == 1
    assert join.attributes["langgraph.step"] == 2
    assert sorted(join.inputs["log"]) == ["a", "b"]
    _assert_parent_links_match_run_ids(handler)
    _export_and_load(handler, tmp_path)


def test_subgraph_nesting_parent_links(tmp_path):
    sub = StateGraph(State)
    sub.add_node("inner", lambda s: {"log": ["inner"]})
    sub.add_edge(START, "inner")
    sub.add_edge("inner", END)
    g = StateGraph(State)
    g.add_node("outer", sub.compile())
    g.add_edge(START, "outer")
    g.add_edge("outer", END)
    handler = SageLangChainCallback(trace_id="lg-sub")
    with handler:
        g.compile().invoke({"x": 0, "log": []}, config={"callbacks": [handler]})
    handler.assert_complete()

    by_id = _by_id(handler)
    [root] = _roots(handler)
    [inner] = [s for s in _spans(handler) if s.name == "inner"]
    chain = [inner]
    while chain[-1].parent_id:
        chain.append(by_id[chain[-1].parent_id])
    assert [s.name for s in chain] == ["inner", "LangGraph", "outer", "LangGraph"]
    assert chain[-1] is root
    _assert_parent_links_match_run_ids(handler)
    _export_and_load(handler, tmp_path)


def test_interrupt_and_resume_is_cancelled_not_error(tmp_path):
    def ask(state):
        answer = interrupt({"question": "approve refund?"})
        return {"log": [f"answer={answer}"]}

    g = StateGraph(State)
    g.add_node("ask", ask)
    g.add_edge(START, "ask")
    g.add_edge("ask", END)
    app = g.compile(checkpointer=InMemorySaver())
    handler = SageLangChainCallback(trace_id="lg-interrupt")
    config = {"callbacks": [handler], "configurable": {"thread_id": "thread-7"}}
    with handler:
        first = app.invoke({"x": 0, "log": []}, config=config)
        assert "__interrupt__" in first
        final = app.invoke(Command(resume="yes"), config=config)
    assert final["log"] == ["answer=yes"]
    handler.assert_complete()

    asks = sorted(_nodes(handler, "ask"), key=lambda s: s.start_time)
    assert [s.status for s in asks] == ["cancelled", "ok"]
    assert asks[0].error is None
    assert asks[0].data["langgraph"] == {"interrupted": True, "interrupts": [{"question": "approve refund?"}]}
    assert asks[1].outputs == {"log": ["answer=yes"]}
    roots = _roots(handler)
    assert len(roots) == 2
    assert {r.attributes.get("langgraph.thread_id") for r in roots} == {"thread-7"}
    loaded = _export_and_load(handler, tmp_path)
    assert loaded.status == "completed"


def test_interrupt_payload_is_redacted(tmp_path):
    def ask(state):
        interrupt({"api_key": "canary-interrupt-key-417", "question": "ok?"})
        return {}

    g = StateGraph(State)
    g.add_node("ask", ask)
    g.add_edge(START, "ask")
    g.add_edge("ask", END)
    app = g.compile(checkpointer=InMemorySaver())
    handler = SageLangChainCallback(trace_id="lg-interrupt-redact")
    with handler:
        app.invoke({"x": 0, "log": []}, config={"callbacks": [handler], "configurable": {"thread_id": "t"}})
    path = handler.recorder.export(tmp_path / "redact.sage.json")
    text = path.read_text(encoding="utf-8")
    assert "canary-interrupt-key-417" not in text and "ok?" in text


def test_parent_command_handoff_is_ok_not_error(tmp_path):
    def hand_off(state):
        return Command(graph=Command.PARENT, goto="finish", update={"log": ["handoff"]})

    sub = StateGraph(State)
    sub.add_node("hand_off", hand_off)
    sub.add_edge(START, "hand_off")
    g = StateGraph(State)
    g.add_node("worker", sub.compile())
    g.add_node("finish", lambda s: {"log": ["finish"]})
    g.add_edge(START, "worker")
    g.add_edge("finish", END)
    handler = SageLangChainCallback(trace_id="lg-parent-cmd")
    with handler:
        result = g.compile().invoke({"x": 0, "log": []}, config={"callbacks": [handler]})
    assert result["log"] == ["handoff", "finish"]
    handler.assert_complete()
    assert not [s for s in _spans(handler) if s.status == "error"]
    controls = [s for s in _spans(handler) if (s.data.get("langgraph") or {}).get("control") == "ParentCommand"]
    assert controls and all(s.status == "ok" for s in controls)
    assert _export_and_load(handler, tmp_path).status == "completed"


@pytest.mark.parametrize("handler_cls", [SageLangChainCallback, AsyncSageLangChainCallback])
def test_async_graph(tmp_path, handler_cls):
    handler = handler_cls(trace_id=f"lg-async-{handler_cls.__name__}")

    async def run() -> Any:
        with handler:
            return await _linear_graph().ainvoke({"x": 1, "log": []}, config={"callbacks": [handler]})

    assert asyncio.run(run()) == {"x": 4, "log": ["one", "two"]}
    handler.assert_complete()
    assert len(_nodes(handler, "one")) == 1 and len(_nodes(handler, "two")) == 1
    _assert_parent_links_match_run_ids(handler)
    _export_and_load(handler, tmp_path)


def test_node_exception_is_error_and_bundle_failed(tmp_path):
    def boom(state):
        raise PermissionError("refund ledger locked")

    g = StateGraph(State)
    g.add_node("boom", boom)
    g.add_edge(START, "boom")
    g.add_edge("boom", END)
    handler = SageLangChainCallback(trace_id="lg-error")
    with pytest.raises(PermissionError):
        with handler:
            g.compile().invoke({"x": 0, "log": []}, config={"callbacks": [handler]})
    handler.assert_complete()
    [node] = _nodes(handler, "boom")
    assert node.status == "error" and node.error.type == "PermissionError"
    assert _export_and_load(handler, tmp_path).status == "failed"


def test_graph_stream_mode_updates(tmp_path):
    handler = SageLangChainCallback(trace_id="lg-stream")
    with handler:
        updates = list(_linear_graph().stream({"x": 1, "log": []}, config={"callbacks": [handler]},
                                              stream_mode="updates"))
    assert [list(u) for u in updates] == [["one"], ["two"]]
    handler.assert_complete()
    [root] = _roots(handler)
    assert root.inputs == {"x": 1, "log": []}
    _export_and_load(handler, tmp_path)
