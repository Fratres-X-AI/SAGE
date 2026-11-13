"""Real OpenAI Agents SDK runs (pinned in the ``openai-agents`` extra) recorded by the SAGE processor.

A deterministic in-process ``Model`` stands in for the LLM: no network, no API key.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

pytest.importorskip("agents")

from agents import (
    Agent,
    GuardrailFunctionOutput,
    InputGuardrailTripwireTriggered,
    ModelSettings,
    RunConfig,
    Runner,
    function_tool,
    input_guardrail,
    set_trace_processors,
)
from agents.handoffs import Handoff
from agents.items import ModelResponse
from agents.models.interface import Model, ModelTracing
from agents.testing.model import assistant_message, function_call
from agents.tracing import SpanError, generation_span
from agents.usage import Usage

from sage.adapters.openai_agents import CaptureIncompleteError, SageOpenAIAgentsProcessor
from sage.bundle_io import save_bundle
from sage.verify import verify_artifact

SECRET = "sk-agentsSECRET0123456789abc"


class FakeModel(Model):
    """Replays scripted turns. Records a generation span with input, output, model and usage,
    the same fields the SDK's OpenAI chat-completions model records."""

    def __init__(self, turns: list[Any], name: str = "fake-model") -> None:
        self.turns = list(turns)
        self.name = name
        self.calls = 0

    async def get_response(
        self,
        system_instructions,
        input,
        model_settings,
        tools,
        output_schema,
        handoffs,
        tracing: ModelTracing,
        *,
        previous_response_id=None,
        conversation_id=None,
        prompt=None,
    ) -> ModelResponse:
        self.calls += 1
        turn = self.turns.pop(0)
        if callable(turn):
            turn = turn(input)
        messages = [{"role": "system", "content": system_instructions}] if system_instructions else []
        messages += [{"role": "user", "content": input}] if isinstance(input, str) else list(input)
        with generation_span(
            model=self.name,
            model_config={"temperature": model_settings.temperature},
            disabled=tracing.is_disabled(),
        ) as span:
            if tracing.include_data():
                span.span_data.input = json.loads(json.dumps(messages, default=str))
            if isinstance(turn, Exception):
                span.set_error(SpanError(message="Error", data={"name": type(turn).__name__, "message": str(turn)}))
                raise turn
            if tracing.include_data():
                span.span_data.output = [item.model_dump(mode="json", exclude_none=True) for item in turn]
            usage = Usage(requests=1, input_tokens=10, output_tokens=5, total_tokens=15)
            span.span_data.usage = {"input_tokens": 10, "output_tokens": 5}
            return ModelResponse(output=list(turn), usage=usage, response_id=None)

    def stream_response(self, *args: Any, **kwargs: Any):  # pragma: no cover - not exercised
        raise NotImplementedError


@pytest.fixture(autouse=True)
def _offline(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    for name in ("OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_ORG_ID"):
        monkeypatch.delenv(name, raising=False)
    yield
    set_trace_processors([])


@pytest.fixture
def processor(tmp_path):
    proc = SageOpenAIAgentsProcessor(trace_id="agents-test", journal_dir=str(tmp_path / "journal"))
    set_trace_processors([proc])
    return proc


@function_tool
def lookup_order(order_id: str) -> str:
    """Look up an order status."""
    return f"order {order_id}: shipped"


@function_tool
def flaky_refund(order_id: str) -> str:
    """Issue a refund."""
    raise ValueError(f"refund backend down for {order_id}")


def _spans(proc: SageOpenAIAgentsProcessor):
    return list(proc.recorder.bundle.spans)


def _by_sdk_type(proc, sdk_type: str):
    return [s for s in _spans(proc) if s.attributes.get("openai_agents.span_type") == sdk_type]


def _children(proc, parent):
    return [s for s in _spans(proc) if s.parent_id == parent.span_id]


def test_tool_call_then_final_message(processor, tmp_path):
    model = FakeModel(
        [
            [function_call("lookup_order", {"order_id": "42"}, call_id="call_1")],
            [assistant_message("Order 42 has shipped.")],
        ]
    )
    agent = Agent(name="support", instructions="Help with orders.", model=model, tools=[lookup_order])
    with processor:
        result = Runner.run_sync(agent, "Where is order 42?")
    assert result.final_output == "Order 42 has shipped."
    processor.assert_complete()

    (trace_span,) = [s for s in _spans(processor) if s.attributes.get("openai_agents.span_type") is None]
    assert trace_span.type == "chain" and trace_span.parent_id is None
    (agent_span,) = _by_sdk_type(processor, "agent")
    assert agent_span.type == "agent" and agent_span.agent_id == "support"
    assert agent_span.data["tools"] == ["lookup_order"]

    generations = _by_sdk_type(processor, "generation")
    assert len(generations) == 2 and all(g.type == "llm" for g in generations)
    assert generations[0].data["model"] == "fake-model"
    assert generations[0].data["usage"] == {"input_tokens": 10, "output_tokens": 5}
    assert generations[0].inputs["messages"][-1]["content"] == "Where is order 42?"

    (tool,) = _by_sdk_type(processor, "function")
    assert tool.type == "tool" and tool.status == "ok"
    assert tool.data["tool_name"] == "lookup_order"
    assert json.loads(tool.data["input"]) == {"order_id": "42"}
    assert tool.data["output"] == "order 42: shipped"
    assert tool.data["success"] is True

    # Nesting: every SDK span hangs off its SDK parent; the outermost under the trace span.
    by_sdk_id = {s.attributes.get("openai_agents.span_id"): s for s in _spans(processor)}
    for span in _spans(processor):
        sdk_parent = span.attributes.get("openai_agents.parent_id")
        if sdk_parent:
            assert span.parent_id == by_sdk_id[sdk_parent].span_id
        elif span is not trace_span:
            assert span.parent_id == trace_span.span_id
    assert _is_descendant(processor, agent_span, trace_span)
    assert _is_descendant(processor, tool, agent_span)
    assert all(_is_descendant(processor, g, agent_span) for g in generations)

    bundle = processor.recorder.finalized_bundle()
    path = save_bundle(bundle, tmp_path / "run.sage.json")
    assert verify_artifact(path)["ok"] is True
    assert bundle.status == "completed"


def _is_descendant(proc, span, ancestor) -> bool:
    by_id = {s.span_id: s for s in _spans(proc)}
    current = span
    while current.parent_id:
        if current.parent_id == ancestor.span_id:
            return True
        current = by_id[current.parent_id]
    return False


def test_handoff_between_two_agents(processor):
    billing_model = FakeModel([[assistant_message("Refund approved.")]], name="billing-model")
    billing = Agent(name="billing", instructions="Handle refunds.", model=billing_model)
    triage_model = FakeModel(
        [[function_call(Handoff.default_tool_name(billing), {}, call_id="call_h")]], name="triage-model"
    )
    triage = Agent(name="triage", instructions="Route.", model=triage_model, handoffs=[billing])
    with processor:
        result = Runner.run_sync(triage, "I want a refund")
    assert result.final_output == "Refund approved."
    processor.assert_complete()

    agents = {s.agent_id: s for s in _by_sdk_type(processor, "agent")}
    assert set(agents) == {"triage", "billing"}
    assert agents["triage"].data["handoffs"] == ["billing"]
    (handoff,) = _by_sdk_type(processor, "handoff")
    assert handoff.type == "handoff"
    assert handoff.data["from_agent"] == "triage" and handoff.data["to_agent"] == "billing"
    assert _is_descendant(processor, handoff, agents["triage"])
    assert not _is_descendant(processor, agents["billing"], agents["triage"])
    assert {g.data["model"] for g in _by_sdk_type(processor, "generation")} == {"triage-model", "billing-model"}
    billing_gen = next(g for g in _by_sdk_type(processor, "generation") if g.data["model"] == "billing-model")
    assert _is_descendant(processor, billing_gen, agents["billing"])


def test_guardrail_tripwire(processor, tmp_path):
    @input_guardrail(run_in_parallel=False)
    def block_refunds(ctx, agent, user_input) -> GuardrailFunctionOutput:
        return GuardrailFunctionOutput(output_info={"reason": "refunds"}, tripwire_triggered="refund" in str(user_input))

    model = FakeModel([[assistant_message("never")]])
    agent = Agent(name="guarded", instructions="x", model=model, input_guardrails=[block_refunds])
    with pytest.raises(InputGuardrailTripwireTriggered):
        with processor:
            Runner.run_sync(agent, "refund me now")
    processor.assert_complete()
    assert model.calls == 0
    (guard,) = _by_sdk_type(processor, "guardrail")
    assert guard.type == "guardrail" and guard.name == "block_refunds"
    assert guard.status == "error" and guard.error.type == "GuardrailTripwireTriggered"
    assert guard.data["triggered"] is True and guard.data["decision"] == "block"
    (agent_span,) = _by_sdk_type(processor, "agent")
    assert _is_descendant(processor, guard, agent_span)
    # The SDK attaches the tripwire error to the enclosing turn span.
    (turn,) = _by_sdk_type(processor, "turn")
    assert guard.parent_id == turn.span_id
    assert turn.status == "error" and turn.error.message == "Guardrail tripwire triggered"
    bundle = processor.recorder.finalized_bundle()
    assert bundle.status == "failed"
    assert verify_artifact(save_bundle(bundle, tmp_path / "g.sage.json"))["ok"] is True


def test_exception_in_tool(processor):
    model = FakeModel(
        [
            [function_call("flaky_refund", {"order_id": "7"}, call_id="call_r")],
            [assistant_message("Sorry, refunds are unavailable.")],
        ]
    )
    agent = Agent(name="support", instructions="x", model=model, tools=[flaky_refund])
    with processor:
        result = Runner.run_sync(agent, "refund order 7")
    assert result.final_output == "Sorry, refunds are unavailable."
    processor.assert_complete()
    (tool,) = _by_sdk_type(processor, "function")
    assert tool.status == "error"
    assert tool.data["success"] is False
    assert tool.error.message == "Error running tool (non-fatal)"
    assert tool.data["error_data"]["tool_name"] == "flaky_refund"
    # openai-agents 0.24 replaces the exception text in the span before processors see it.
    assert tool.data["error_data"]["error"] == "Tool execution failed. Error details are redacted."
    assert tool.data["output"] == "An error occurred while running the tool. Please try again."


def test_model_exception_propagates_and_closes_spans(processor):
    model = FakeModel([RuntimeError("provider timeout")])
    agent = Agent(name="support", instructions="x", model=model)
    with pytest.raises(RuntimeError):
        with processor:
            Runner.run_sync(agent, "hi")
    processor.assert_complete()
    (gen,) = _by_sdk_type(processor, "generation")
    assert gen.status == "error"
    assert gen.error.type == "RuntimeError" and gen.error.message == "Error"
    assert gen.data["error_data"]["message"] == "provider timeout"
    assert processor.recorder.finalized_bundle().status == "failed"


def test_async_runner_and_task_turn_spans(processor):
    model = FakeModel([[assistant_message("done")]])
    agent = Agent(name="a", instructions="x", model=model)

    async def main():
        return await Runner.run(agent, "go", run_config=RunConfig(workflow_name="async-wf"))

    with processor:
        result = asyncio.run(main())
    assert result.final_output == "done"
    processor.assert_complete()
    roots = [s for s in _spans(processor) if s.parent_id is None]
    assert [r.name for r in roots] == ["async-wf"]
    task_or_turn = _by_sdk_type(processor, "task") + _by_sdk_type(processor, "turn")
    assert task_or_turn and all(s.type == "chain" for s in task_or_turn)


def test_secret_in_prompt_is_redacted(processor, tmp_path):
    model = FakeModel(
        [
            [function_call("lookup_order", {"order_id": SECRET}, call_id="call_s")],
            [assistant_message(f"echo {SECRET}")],
        ]
    )
    agent = Agent(name="support", instructions="x", model=model, tools=[lookup_order])
    with processor:
        Runner.run_sync(agent, f"my key is {SECRET}")
    processor.assert_complete()
    journal_text = "".join(
        p.read_text(encoding="utf-8", errors="replace") for p in (tmp_path / "journal").rglob("*") if p.is_file()
    )
    assert journal_text and SECRET not in journal_text
    path = save_bundle(processor.recorder.finalized_bundle(), tmp_path / "s.sage.json")
    assert SECRET not in path.read_text(encoding="utf-8")
    assert "[REDACTED]" in path.read_text(encoding="utf-8")


def test_trace_include_sensitive_data_false_records_no_messages(processor):
    model = FakeModel([[assistant_message("ok")]])
    agent = Agent(name="a", instructions="x", model=model)
    with processor:
        Runner.run_sync(agent, f"secret {SECRET}", run_config=RunConfig(trace_include_sensitive_data=False))
    (gen,) = _by_sdk_type(processor, "generation")
    assert gen.inputs["messages"] is None


def test_capture_errors_surface_in_assert_complete(processor):
    class Broken:
        trace_id = "trace_x"
        name = "x"

        @property
        def group_id(self):
            raise RuntimeError("boom")

    processor.on_trace_start(Broken())
    processor.on_span_end(type("S", (), {"span_id": "span_unknown", "span_data": None, "error": None})())
    with pytest.raises(CaptureIncompleteError) as exc:
        processor.assert_complete()
    assert "capture_errors=1" in str(exc.value) and "unknown_events=1" in str(exc.value)


def test_attach_factory_registers_processor():
    from agents.tracing import get_trace_provider

    from sage.adapters.openai_agents import attach_openai_agents_processor

    proc = attach_openai_agents_processor(trace_id="attached", exclusive=True)
    assert get_trace_provider()._multi_processor._processors == (proc,)
    model = FakeModel([[assistant_message("ok")]])
    with proc:
        Runner.run_sync(Agent(name="a", instructions="x", model=model), "go")
    proc.assert_complete()
    assert proc.recorder.bundle.bundle_id == "attached"
    assert {s.type for s in proc.recorder.bundle.spans} >= {"chain", "agent", "llm"}


def test_model_settings_reach_generation_span(processor):
    model = FakeModel([[assistant_message("ok")]])
    agent = Agent(name="a", instructions="x", model=model, model_settings=ModelSettings(temperature=0.3))
    with processor:
        Runner.run_sync(agent, "go")
    (gen,) = _by_sdk_type(processor, "generation")
    assert gen.data["parameters"] == {"temperature": 0.3}
