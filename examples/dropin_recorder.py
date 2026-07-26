"""Three-line drop-in around a custom agent loop."""

from pathlib import Path

from sage import SageRecorder


def agent_run(task: str) -> str:
    # Stand-in for LangChain / CrewAI / AutoGen / custom loops.
    return f"done:{task}"


def main() -> None:
    out = Path(__file__).resolve().parent / "dropin_incident.sage.json"
    with SageRecorder(trace_id="user-123", auto_export=out) as recorder:
        with recorder.agent_step("run", inputs={"task": "demo"}):
            with recorder.llm_call("think") as llm:
                llm.set_model("demo-llm")
                llm.set_input(prompt="plan the task")
                llm.set_output(text="call tool")
            with recorder.tool_call("echo", inputs={"x": 1}) as tool:
                result = agent_run("demo")
                tool.set_output(result=result)
    print(out)


if __name__ == "__main__":
    main()
