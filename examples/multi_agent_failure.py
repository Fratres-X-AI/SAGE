"""Multi-agent failure: handoff + stale retrieval + tool schema error."""

from __future__ import annotations

from sage.recorder import SageRecorder


def run_multi_agent_failure() -> str:
    with SageRecorder(
        "multi_agent_stale_retrieval",
        framework="custom",
        environment="demo",
        metadata={"failure_mode": "stale_retrieval_schema"},
    ) as recorder:
        with recorder.agent_step(
            "orchestrator",
            agent_id="orchestrator",
            agent_role="coordinator",
            inputs={"goal": "update customer tier"},
            data={"goal": "update customer tier", "plan_step": "delegate", "next_action": "handoff"},
        ) as orch:
            orch.set_attributes(state_hash="state_v1")

            with recorder.handoff(
                "delegate_to_researcher",
                from_agent="orchestrator",
                to_agent="researcher",
                context_passed={"goal": "fetch profile", "customer_id": "cust_42"},
            ) as handoff:
                handoff.set_output(accepted=True)

            with recorder.retrieval(
                "fetch_customer_profile",
                agent_id="researcher",
                agent_role="retriever",
                inputs={"query": "customer profile cust_42", "customer_id": "cust_42"},
            ) as retrieval:
                retrieval.set_output(
                    documents=[
                        {
                            "id": "doc_1",
                            "score": 0.91,
                            "schema_version": "v1",
                            "stale": True,
                            "content_hash": "abc123",
                        }
                    ]
                )
                retrieval.set_data(source="profile_index", query="customer profile cust_42")
                retrieval.mark_root_cause("stale schema v1 documents", score=0.9)

            with recorder.llm_call(
                "plan_update",
                agent_id="planner",
                agent_role="planner",
                inputs={"prompt": "Choose tool args for tier update"},
            ) as llm:
                llm.set_model("demo-llm", temperature=0.0)
                llm.set_output(response={"tool": "update_tier", "args": {"schema": "v1", "tier": "gold"}})
                llm.set_usage(prompt_tokens=120, completion_tokens=40, total=160)
                llm.set_data(finish_reason="stop")

            with recorder.tool_call(
                "update_tier",
                agent_id="executor",
                agent_role="tools",
                inputs={"tier": "gold", "schema": "v1"},
                data={
                    "tool_name": "update_tier",
                    "input": {"tier": "gold", "schema": "v1"},
                    "output": {},
                    "success": False,
                    "side_effects": False,
                },
            ) as tool:
                tool.set_output(error="schema v2 required; v1 rejected")
                tool.fail("schema drift", error_type="SchemaError")
                orch.fail("tool rejected stale schema", error_type="CascadeError")

        recorder.mark_failure(retrieval.span.span_id, note="stale retrieval schema")

    path = recorder.export("examples/multi_agent_incident.sage.json")
    return str(path)


if __name__ == "__main__":
    print(run_multi_agent_failure())
