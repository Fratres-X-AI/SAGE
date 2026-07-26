"""Example: stale retrieval causes a tool schema mismatch and failed agent run."""

from __future__ import annotations

from sage.recorder import SageRecorder


def run_failing_agent() -> str:
    with SageRecorder(
        "stale_retrieval_example",
        metadata={"failure_mode": "stale_retrieval_schema", "env": "demo"},
        agent_id="support_agent",
    ) as recorder:
        with recorder.agent_step("support_agent", inputs={"goal": "update customer tier"}) as step:
            step.set_attributes(confidence=0.82)
            step.set_data(goal="update customer tier", plan_step="retrieve", next_action="tool")
            with recorder.retrieval(
                "fetch_customer_profile",
                inputs={"query": "cust_42", "customer_id": "cust_42"},
            ) as retrieval:
                retrieval.set_output(
                    documents=[{"id": "d1", "tier": "gold", "schema_version": "v1", "stale": True}]
                )
                retrieval.mark_root_cause("stale schema v1", score=0.88)
            with recorder.llm_call(
                "plan_update",
                inputs={"prompt": "Choose tool args for tier update"},
            ) as llm:
                llm.set_model("demo-llm", temperature=0.0)
                llm.set_output(response={"tool": "update_tier", "args": {"tier": "gold", "schema": "v1"}})
                llm.set_usage(prompt_tokens=80, completion_tokens=20, total=100)
            with recorder.tool_call(
                "update_tier",
                inputs={"tier": "gold", "schema": "v1"},
            ) as tool:
                tool.set_output(error="schema v2 required; v1 rejected")
                tool.fail("schema drift", error_type="SchemaError")
                step.fail("tool rejected stale schema")
        recorder.mark_failure(retrieval.span.span_id, note="stale retrieval")
    return str(recorder.export("examples/incident.sage.json"))


if __name__ == "__main__":
    print(run_failing_agent())
