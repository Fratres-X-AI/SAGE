"""Circular multi-agent handoffs (A→B→A) before a terminal error."""

from __future__ import annotations

from sage.recorder import SageRecorder


def run_cyclic_agents(loops: int = 3) -> str:
    with SageRecorder(
        "cyclic_agent_recursion",
        framework="custom",
        environment="demo",
        metadata={"failure_mode": "cyclic_handoff"},
    ) as recorder:
        with recorder.agent_step(
            "agent_a",
            agent_id="agent_a",
            agent_role="worker",
            inputs={"goal": "resolve ticket"},
            data={"goal": "resolve ticket", "plan_step": "loop", "next_action": "handoff"},
        ) as a:
            for i in range(loops):
                with recorder.handoff(
                    f"a_to_b_{i}",
                    from_agent="agent_a",
                    to_agent="agent_b",
                    context_passed={"iteration": i, "note": "ping"},
                ):
                    pass
                with recorder.agent_step(
                    f"agent_b_work_{i}",
                    agent_id="agent_b",
                    agent_role="worker",
                    inputs={"iteration": i},
                    data={"goal": "ping-pong", "plan_step": str(i), "next_action": "handoff"},
                ):
                    pass
                with recorder.handoff(
                    f"b_to_a_{i}",
                    from_agent="agent_b",
                    to_agent="agent_a",
                    context_passed={"iteration": i, "note": "pong"},
                ):
                    pass
            with recorder.tool_call(
                "explode",
                agent_id="agent_a",
                inputs={"reason": "recursion_budget_exceeded"},
            ) as tool:
                tool.set_output(error="max handoff depth exceeded")
                tool.fail("cyclic recursion budget exceeded", error_type="RecursionError")
                a.fail("agent loop exhausted")
        recorder.mark_failure(tool.span.span_id, note="cyclic handoff exhaustion")
    return str(recorder.export("examples/cyclic_agents.sage.json"))


if __name__ == "__main__":
    print(run_cyclic_agents())
