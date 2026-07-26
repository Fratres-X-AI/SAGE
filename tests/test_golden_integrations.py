from __future__ import annotations

from uuid import uuid4

from sage.adapters.langchain_callback import SageLangChainCallback
from sage.adapters.run_wrapper import autogen_chat, crewai_kickoff, wrap_agent_run
from sage.handoff import create_handoff
from sage.policy import load_policy
from sage.verify import verify_artifact
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_golden_langchain_callback_to_strict_handoff(tmp_path):
    with SageLangChainCallback(trace_id="lc-gold", journal_dir=str(tmp_path / "j")) as cb:
        run = uuid4()
        cb.on_llm_start({"name": "ChatOpenAI"}, ["hello"], run_id=run)
        cb.on_llm_end(
            type("R", (), {"generations": [[type("G", (), {"text": "world"})()]]})(),
            run_id=run,
        )
        tool_run = uuid4()
        cb.on_tool_start({"name": "search"}, "query", run_id=tool_run)
        cb.on_tool_end("docs", run_id=tool_run)
    path = cb.recorder.export(tmp_path / "lc.sage.json")
    kit = create_handoff(path, tmp_path / "kit", hmac_key="gold-lc")
    report = verify_artifact(
        kit / "evidence.sage.tar.gz",
        hmac_key="gold-lc",
        check_witness=True,
        witness_key="gold-lc",
        policy=load_policy(ROOT / "policies" / "strict.json"),
    )
    assert report["ok"]
    assert any(s.type == "llm" for s in cb.recorder.finalized_bundle().spans)


def test_golden_crewai_and_autogen_wrappers(tmp_path):
    class Crew:
        def kickoff(self, prompt: str) -> str:
            return f"crew:{prompt}"

    class Agent:
        def initiate_chat(self, msg: str) -> str:
            return f"ag:{msg}"

    crew = Crew()
    with crewai_kickoff(crew, journal_dir=str(tmp_path / "c")) as rec:
        assert crew.kickoff("x") == "crew:x"
        path = rec.export(tmp_path / "crew.sage.json")
    verify_artifact(path, check_blobs=False)

    agent = Agent()
    with autogen_chat(agent, journal_dir=str(tmp_path / "a")) as rec2:
        assert agent.initiate_chat("y") == "ag:y"
        path2 = rec2.export(tmp_path / "ag.sage.json")
    verify_artifact(path2, check_blobs=False)

    class Custom:
        def run(self, q: str) -> str:
            return q.upper()

    custom = Custom()
    with wrap_agent_run(custom, method="run", journal_dir=str(tmp_path / "w")) as rec3:
        assert custom.run("hi") == "HI"
        rec3.export(tmp_path / "w.sage.json")
