"""Real PydanticAI runs (pinned in the ``pydantic-ai`` extra) recorded through SagePydanticAI.

Models are PydanticAI's built-in offline ``TestModel`` and ``FunctionModel``: no network, no keys.
"""

from __future__ import annotations

import asyncio
import json

import pytest

pytest.importorskip("pydantic_ai")
pytest.importorskip("opentelemetry.sdk.trace")

from pydantic import BaseModel
from pydantic_ai import Agent, ModelRetry
from pydantic_ai.messages import ModelMessage, ModelResponse, TextPart, ToolCallPart
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.models.test import TestModel

from sage.adapters.pydantic_ai import CaptureIncompleteError, SagePydanticAI
from sage.bundle_io import save_bundle
from sage.verify import verify_artifact

SECRET = "sk-pydanticSECRET0123456789"


@pytest.fixture(autouse=True)
def _offline(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    for name in ("OPENAI_API_KEY", "LOGFIRE_TOKEN", "OTEL_EXPORTER_OTLP_ENDPOINT"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def sage(tmp_path):
    return SagePydanticAI(trace_id="pai-test", journal_dir=str(tmp_path / "journal"))


class City(BaseModel):
    name: str
    population: int


def _of_type(sage, span_type):
    return [s for s in sage.recorder.bundle.spans if s.type == span_type]


def test_tool_call_and_structured_output(sage, tmp_path):
    agent = sage.instrument(Agent(TestModel(), output_type=City, name="geo"))

    @agent.tool_plain
    def population(city: str) -> int:
        """Population of a city."""
        return 8_000_000

    with sage:
        result = agent.run_sync("Biggest city?")
    assert isinstance(result.output, City)
    sage.assert_complete()

    (agent_span,) = _of_type(sage, "agent")
    assert agent_span.name == "invoke_agent geo" and agent_span.agent_id == "geo"
    assert agent_span.parent_id is None
    assert agent_span.data["output"] == result.output.model_dump()
    chats = _of_type(sage, "llm")
    assert len(chats) == 2 and all(c.parent_id == agent_span.span_id for c in chats)
    assert chats[0].data["model"] == "test"
    assert chats[0].data["usage"]["input_tokens"] > 0
    assert chats[0].data["input"]["messages"][0]["parts"][0]["content"] == "Biggest city?"
    final_call = chats[-1].data["output"]["messages"][0]["parts"][0]
    assert final_call["type"] == "tool_call" and final_call["name"] == "final_result"
    (tool,) = _of_type(sage, "tool")
    assert tool.parent_id == agent_span.span_id
    assert tool.data["tool_name"] == "population" and tool.status == "ok"
    # OTel attributes are strings; PydanticAI writes the tool result as text.
    assert tool.data["output"] == "8000000"
    assert tool.attributes["otel.span_id"] and "sage.seq" in tool.attributes

    bundle = sage.recorder.finalized_bundle()
    assert bundle.status == "completed"
    path = save_bundle(bundle, tmp_path / "pai.sage.json")
    assert verify_artifact(path)["ok"] is True


def test_tool_retry_then_success(sage):
    agent = sage.instrument(Agent(TestModel(), name="retrier"))
    calls = {"n": 0}

    @agent.tool_plain
    def lookup(q: str) -> str:
        """Look something up."""
        calls["n"] += 1
        if calls["n"] == 1:
            raise ModelRetry("backend busy")
        return "found"

    with sage:
        agent.run_sync("go")
    sage.assert_complete()
    first, second = _of_type(sage, "tool")
    assert first.status == "error"
    assert first.error.type == "pydantic_ai.exceptions.ToolRetryError"
    assert first.error.message == "backend busy"
    assert first.data["retry"] == {"cause": "model_retry", "attempt": 1, "max_retries": 1}
    assert second.status == "ok" and second.data["output"] == "found"
    assert len(_of_type(sage, "llm")) == 3


def test_tool_raising_exception_fails_the_run(sage):
    agent = sage.instrument(Agent(TestModel(), name="breaker"))

    @agent.tool_plain
    def explode(x: str) -> str:
        """Always fails."""
        raise RuntimeError(f"database unreachable for {x}")

    with pytest.raises(RuntimeError):
        with sage:
            agent.run_sync("go")
    sage.assert_complete()
    (tool,) = _of_type(sage, "tool")
    assert tool.status == "error" and tool.error.type == "RuntimeError"
    assert "database unreachable" in tool.error.message
    assert tool.data["success"] is False
    (agent_span,) = _of_type(sage, "agent")
    assert agent_span.status == "error"
    assert sage.recorder.finalized_bundle().status == "failed"


def test_function_model_output_validation_retry(sage):
    seen = {"n": 0}

    def model_fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        seen["n"] += 1
        if seen["n"] == 1:
            return ModelResponse(parts=[ToolCallPart("final_result", {"name": "Paris"})])
        return ModelResponse(parts=[ToolCallPart("final_result", {"name": "Paris", "population": 2_100_000})])

    agent = sage.instrument(Agent(FunctionModel(model_fn), output_type=City, name="validator"))
    with sage:
        result = agent.run_sync("Capital of France?")
    assert result.output.population == 2_100_000
    sage.assert_complete()
    chats = _of_type(sage, "llm")
    assert len(chats) == 2
    assert chats[0].data["model"] == "function:model_fn:"
    retry_prompt = chats[1].data["input"]["messages"]
    assert any(p.get("type") == "tool_call_response" for m in retry_prompt for p in m.get("parts", []))


def test_async_run_and_text_output(sage):
    def model_fn(messages, info):
        return ModelResponse(parts=[TextPart("plain answer")])

    agent = sage.instrument(Agent(FunctionModel(model_fn), name="texter"))

    async def main():
        return await agent.run("hi")

    with sage:
        result = asyncio.run(main())
    assert result.output == "plain answer"
    sage.assert_complete()
    (chat,) = _of_type(sage, "llm")
    assert chat.data["output"]["messages"][0]["parts"][0]["content"] == "plain answer"


def test_include_content_false_drops_prompts(tmp_path):
    sage = SagePydanticAI(include_content=False)
    agent = sage.instrument(Agent(TestModel(custom_output_text="ok"), name="quiet"))
    with sage:
        agent.run_sync(f"secret {SECRET}")
    (chat,) = _of_type(sage, "llm")
    # Message structure is kept; the text parts carry no content.
    assert chat.data["input"] == {"messages": [{"role": "user", "parts": [{"type": "text"}]}]}
    assert SECRET not in json.dumps(chat.attributes) and SECRET not in json.dumps(chat.data)


def test_secret_in_prompt_is_redacted(sage, tmp_path):
    agent = sage.instrument(Agent(TestModel(), name="leaky"))

    @agent.tool_plain
    def echo(text: str) -> str:
        """Echo."""
        return f"echo {SECRET}"

    with sage:
        agent.run_sync(f"my key is {SECRET}")
    sage.assert_complete()
    journal_text = "".join(
        p.read_text(encoding="utf-8", errors="replace") for p in (tmp_path / "journal").rglob("*") if p.is_file()
    )
    assert journal_text and SECRET not in journal_text
    path = save_bundle(sage.recorder.finalized_bundle(), tmp_path / "s.sage.json")
    text = path.read_text(encoding="utf-8")
    assert SECRET not in text and "[REDACTED]" in text


def test_instrument_all_and_existing_provider(sage):
    from opentelemetry.sdk.trace import TracerProvider
    from pydantic_ai.models.instrumented import InstrumentationSettings

    previous = Agent._instrument_default
    try:
        sage.instrument_all()
        agent = Agent(TestModel(custom_output_text="ok"), name="global")
        with sage:
            agent.run_sync("hi")
    finally:
        Agent.instrument_all(previous)
    assert [s.type for s in sage.recorder.bundle.spans].count("agent") == 1

    other = SagePydanticAI()
    provider = TracerProvider()
    provider.add_span_processor(other.span_processor)
    agent = Agent(TestModel(custom_output_text="ok"), name="own-provider")
    agent.instrument = InstrumentationSettings(tracer_provider=provider)
    with other:
        agent.run_sync("hi")
    other.assert_complete()
    assert {s.type for s in other.recorder.bundle.spans} == {"agent", "llm"}


def test_capture_errors_surface(sage):
    sage.span_processor.on_end(object())
    with pytest.raises(CaptureIncompleteError) as exc:
        sage.assert_complete()
    assert "capture_errors=1" in str(exc.value)
