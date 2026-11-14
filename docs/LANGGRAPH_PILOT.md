# LangGraph pilot guide

SAGE records LangGraph runs through the same **`SageLangChainCallback`** / **`AsyncSageLangChainCallback`** used for LangChain (`langchain-core` pinned in `pyproject.toml`; `langgraph` pinned in `[langgraph]` extra).

## What CI validates today

`tests/integration_langgraph/test_langgraph_real.py` exercises a real `StateGraph` against pinned **langgraph==1.2.21**:

- Linear graph, conditional edges, `ToolNode`, fan-out / fan-in
- Subgraph nesting (parent links vs LangGraph run ids)
- `ainvoke` and `stream(stream_mode="updates")`
- `interrupt` / `Command(resume=...)`
- Deterministic `FakeListChatModel` and in-memory checkpointing (no live LLM API)

LangChain adapter coverage (invoke, astream, batch, RunnableParallel, retriever events) is in `tests/integration_langchain/`. See [COMPATIBILITY.md](../COMPATIBILITY.md) for version matrix and limits.

## Wiring (minimal)

```python
from sage import SageRecorder
from sage.adapters.langchain_callback import SageLangChainCallback

with SageRecorder("support-flow", journal_dir="run.journal") as rec:
    handler = SageLangChainCallback(recorder=rec)
    graph.invoke({"messages": [("user", "hello")]}, config={"callbacks": [handler]})
    handler.assert_complete()
```

Use a live journal only when you need crash-safe recording; default durability is **`batch`** (see README).

## Not validated in CI (honest scope)

- Live OpenAI / Anthropic models in production graphs
- Remote LangGraph Platform deployment
- Custom checkpointers other than in-memory in tests

Pilot findings on gaps belong in COMPATIBILITY scope notes or new integration tests—prefer one real customer graph as a fixture over guessing.

## After the run

```bash
sage verify-journal run.journal --skip-blobs   # or pack / handoff per VERIFY_RUNBOOK
sage scan <pack or bundle>                     # before sharing externally
```