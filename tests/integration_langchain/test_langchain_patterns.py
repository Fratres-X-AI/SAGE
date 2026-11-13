"""Streaming, batch, RunnableParallel and retriever capture against real langchain-core."""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("langchain_core")

from langchain_core.documents import Document
from langchain_core.language_models.fake_chat_models import FakeListChatModel
from langchain_core.retrievers import BaseRetriever
from langchain_core.runnables import RunnableLambda, RunnableParallel

from sage.adapters.langchain_callback import AsyncSageLangChainCallback, SageLangChainCallback
from sage.bundle_io import load_bundle


@pytest.fixture(autouse=True)
def _no_external_tracing(monkeypatch):
    monkeypatch.setenv("LANGCHAIN_TRACING_V2", "false")
    monkeypatch.setenv("LANGSMITH_TRACING", "false")
    for name in ("LANGCHAIN_API_KEY", "LANGSMITH_API_KEY", "LANGCHAIN_ENDPOINT", "LANGSMITH_ENDPOINT"):
        monkeypatch.delenv(name, raising=False)


def _spans(handler):
    return list(handler.recorder.bundle.spans)


def _export_and_load(handler, tmp_path, name="lc.sage.json"):
    return load_bundle(handler.recorder.export(tmp_path / name), verify=True)


class PolicyDocs(BaseRetriever):
    def _get_relevant_documents(self, query, *, run_manager):
        return [Document(page_content=f"refund policy for {query}", metadata={"doc_id": "P-1"}),
                Document(page_content="escalation policy", metadata={"doc_id": "P-2"})]


class BrokenDocs(BaseRetriever):
    def _get_relevant_documents(self, query, *, run_manager):
        raise ConnectionError("vector store offline")


def test_stream_model_aggregates_tokens_into_one_span(tmp_path):
    handler = SageLangChainCallback(trace_id="lc-stream")
    model = FakeListChatModel(responses=["hello world"])
    with handler:
        text = "".join(c.content for c in model.stream("hi", config={"callbacks": [handler]}))
    assert text == "hello world"
    handler.assert_complete()
    [llm] = _spans(handler)
    assert llm.type == "llm"
    assert llm.outputs["text"] == "hello world"
    assert llm.data["stream"] == {"chunks": len("hello world")}
    _export_and_load(handler, tmp_path)


def test_stream_chain_records_final_inputs(tmp_path):
    chain = RunnableLambda(lambda q: f"Q: {q}", name="pre") | FakeListChatModel(responses=["ab"])
    handler = SageLangChainCallback(trace_id="lc-stream-chain")
    with handler:
        chunks = [c.content for c in chain.stream("refund?", config={"callbacks": [handler]})]
    assert "".join(chunks) == "ab"
    handler.assert_complete()
    root = next(s for s in _spans(handler) if s.parent_id is None)
    assert root.inputs == {"input": "refund?"}
    llm = next(s for s in _spans(handler) if s.type == "llm")
    assert llm.parent_id == root.span_id and llm.data["stream"] == {"chunks": 2}
    assert len(_spans(handler)) == 3
    _export_and_load(handler, tmp_path)


def test_astream_with_async_handler(tmp_path):
    handler = AsyncSageLangChainCallback(trace_id="lc-astream")
    model = FakeListChatModel(responses=["xyz"])

    async def run():
        with handler:
            return "".join([c.content async for c in model.astream("hi", config={"callbacks": [handler]})])

    assert asyncio.run(run()) == "xyz"
    handler.assert_complete()
    [llm] = _spans(handler)
    assert llm.data["stream"] == {"chunks": 3}
    _export_and_load(handler, tmp_path)


def test_batch_concurrent_sibling_runs_under_one_handler(tmp_path):
    def double(x: int) -> int:
        return x * 2

    handler = SageLangChainCallback(trace_id="lc-batch")
    with handler:
        out = RunnableLambda(double, name="dbl").batch(list(range(8)), config={"callbacks": [handler],
                                                                              "max_concurrency": 4})
    assert out == [x * 2 for x in range(8)]
    handler.assert_complete()
    spans = _spans(handler)
    assert len(spans) == 8 and all(s.parent_id is None and s.status == "ok" for s in spans)
    assert sorted(s.outputs["output"] for s in spans) == out
    assert len({s.attributes["langchain.run_id"] for s in spans}) == 8
    _export_and_load(handler, tmp_path)


def test_abatch(tmp_path):
    handler = AsyncSageLangChainCallback(trace_id="lc-abatch")

    async def run():
        with handler:
            return await RunnableLambda(lambda x: x + 1, name="inc").abatch([1, 2, 3], config={"callbacks": [handler]})

    assert asyncio.run(run()) == [2, 3, 4]
    handler.assert_complete()
    assert len(_spans(handler)) == 3
    _export_and_load(handler, tmp_path)


def test_runnable_parallel_branches_share_parent(tmp_path):
    par = RunnableParallel(a=RunnableLambda(lambda x: x + 1, name="a"),
                           b=RunnableLambda(lambda x: x + 2, name="b"))
    handler = SageLangChainCallback(trace_id="lc-par")
    with handler:
        assert par.invoke(1, config={"callbacks": [handler]}) == {"a": 2, "b": 3}
    handler.assert_complete()
    root = next(s for s in _spans(handler) if s.parent_id is None)
    branches = sorted((s for s in _spans(handler) if s.parent_id == root.span_id), key=lambda s: s.name)
    assert [b.name for b in branches] == ["a", "b"]
    assert root.outputs == {"a": 2, "b": 3}
    _export_and_load(handler, tmp_path)


def test_retriever_span(tmp_path):
    handler = SageLangChainCallback(trace_id="lc-retr")
    with handler:
        docs = PolicyDocs().invoke("refunds", config={"callbacks": [handler]})
    assert len(docs) == 2
    handler.assert_complete()
    [span] = _spans(handler)
    assert span.type == "retrieval" and span.name == "PolicyDocs"
    assert span.inputs == {"query": "refunds"}
    assert span.data["document_count"] == 2
    assert span.outputs["documents"][0] == {"page_content": "refund policy for refunds", "metadata": {"doc_id": "P-1"}}
    loaded = _export_and_load(handler, tmp_path)
    assert loaded.spans[0].type == "retrieval"


def test_retriever_error_is_recorded(tmp_path):
    handler = SageLangChainCallback(trace_id="lc-retr-err")
    with pytest.raises(ConnectionError):
        with handler:
            BrokenDocs().invoke("refunds", config={"callbacks": [handler]})
    handler.assert_complete()
    [span] = _spans(handler)
    assert span.status == "error" and span.error.type == "ConnectionError"
    assert _export_and_load(handler, tmp_path).status == "failed"


def test_retriever_output_is_redacted(tmp_path):
    handler = SageLangChainCallback(trace_id="lc-retr-redact")

    class LeakyDocs(BaseRetriever):
        def _get_relevant_documents(self, query, *, run_manager):
            return [Document(page_content="contact", metadata={"api_key": "canary-retriever-key-991"})]

    with handler:
        LeakyDocs().invoke("q", config={"callbacks": [handler]})
    path = handler.recorder.export(tmp_path / "leak.sage.json")
    assert "canary-retriever-key-991" not in path.read_text(encoding="utf-8")
