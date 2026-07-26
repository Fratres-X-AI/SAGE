from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Callable, Iterator

from sage.recorder import SageRecorder


@contextmanager
def wrap_agent_run(
    agent: Any,
    *,
    method: str = "run",
    trace_id: str | None = None,
    framework: str = "custom",
    journal_dir: str | None = None,
    span_type: str = "agent",
) -> Iterator[SageRecorder]:
    """Context manager: temporarily wrap ``agent.<method>`` with SAGE spans.

    Works for CrewAI / AutoGen / custom objects that expose ``run`` / ``kickoff`` /
    ``chat`` without importing those frameworks.
    """
    if not hasattr(agent, method):
        raise AttributeError(f"{type(agent).__name__} has no method {method!r}")
    original: Callable[..., Any] = getattr(agent, method)
    recorder = SageRecorder(
        title=f"{type(agent).__name__}.{method}",
        trace_id=trace_id,
        framework=framework,
        journal_dir=journal_dir,
        register_trace=True,
    )
    recorder.__enter__()

    def bound(*args: Any, **kwargs: Any) -> Any:
        with recorder.span(span_type, method, inputs={"args": str(args)[:2000], "kwargs": str(kwargs)[:2000]}) as handle:
            result = original(*args, **kwargs)
            try:
                handle.set_output(result=str(result)[:4000])
            except Exception:
                pass
            return result

    setattr(agent, method, bound)
    try:
        yield recorder
    finally:
        setattr(agent, method, original)
        recorder.__exit__(None, None, None)


def crewai_kickoff(agent: Any, *, trace_id: str | None = None, journal_dir: str | None = None):
    """Wrap CrewAI-style ``kickoff`` (falls back to ``run``)."""
    method = "kickoff" if hasattr(agent, "kickoff") else "run"
    return wrap_agent_run(
        agent,
        method=method,
        trace_id=trace_id,
        framework="crewai",
        journal_dir=journal_dir,
    )


def autogen_chat(agent: Any, *, trace_id: str | None = None, journal_dir: str | None = None):
    """Wrap AutoGen-style ``initiate_chat`` / ``chat`` / ``run``."""
    for name in ("initiate_chat", "chat", "run"):
        if hasattr(agent, name):
            return wrap_agent_run(
                agent,
                method=name,
                trace_id=trace_id,
                framework="autogen",
                journal_dir=journal_dir,
            )
    raise AttributeError("autogen adapter: no initiate_chat/chat/run method found")
