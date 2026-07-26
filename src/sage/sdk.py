from __future__ import annotations

from functools import wraps
from typing import Any, Callable, TypeVar

from sage.recorder import SageRecorder

F = TypeVar("F", bound=Callable[..., Any])


def instrument(
    name: str | None = None,
    *,
    span_type: str = "agent",
    trace_id: str | None = None,
    framework: str = "custom",
) -> Callable[[F], F]:
    """Decorator: wrap any callable in a SageRecorder + root span (stdlib only)."""

    def decorator(fn: F) -> F:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            title = name or getattr(fn, "__name__", "agent.run")
            with SageRecorder(title, trace_id=trace_id, framework=framework) as recorder:
                with recorder.span(span_type, title) as handle:
                    result = fn(*args, **kwargs)
                    try:
                        handle.set_output(result=result)
                    except Exception:
                        pass
                    return result

        return wrapper  # type: ignore[return-value]

    return decorator


def wrap_run(
    agent: Any,
    *,
    method: str = "run",
    trace_id: str | None = None,
    framework: str = "custom",
) -> SageRecorder:
    """Monkey-patch ``agent.run`` (or ``method``) to record under a live recorder.

    Returns the recorder. Call ``recorder.export(path)`` after the run, or use
    ``auto_export=`` on a surrounding context. This keeps framework deps out of SAGE.
    """
    recorder = SageRecorder(
        title=f"{type(agent).__name__}.{method}",
        trace_id=trace_id,
        framework=framework,
    )
    original = getattr(agent, method)

    def bound(*args: Any, **kwargs: Any) -> Any:
        with recorder.span("agent", method) as handle:
            result = original(*args, **kwargs)
            handle.set_output(result=str(result)[:2000])
            return result

    setattr(agent, method, bound)
    recorder._wrapped_original = (agent, method, original)  # type: ignore[attr-defined]
    return recorder


def unwrap_run(recorder: SageRecorder) -> None:
    pair = getattr(recorder, "_wrapped_original", None)
    if not pair:
        return
    agent, method, original = pair
    setattr(agent, method, original)


class FrameworkAdapter:
    """Minimal adapter surface for LangChain / CrewAI / AutoGen / custom loops."""

    def __init__(self, framework: str, *, trace_id: str | None = None) -> None:
        self.framework = framework
        self.trace_id = trace_id

    def recorder(self, title: str | None = None, **kwargs: Any) -> SageRecorder:
        return SageRecorder(
            title or self.framework,
            trace_id=self.trace_id,
            framework=self.framework,
            **kwargs,
        )

    def __call__(self, title: str | None = None, **kwargs: Any) -> SageRecorder:
        return self.recorder(title, **kwargs)


def langchain(trace_id: str | None = None) -> FrameworkAdapter:
    return FrameworkAdapter("langchain", trace_id=trace_id)


def crewai(trace_id: str | None = None) -> FrameworkAdapter:
    return FrameworkAdapter("crewai", trace_id=trace_id)


def autogen(trace_id: str | None = None) -> FrameworkAdapter:
    return FrameworkAdapter("autogen", trace_id=trace_id)


def custom(trace_id: str | None = None) -> FrameworkAdapter:
    return FrameworkAdapter("custom", trace_id=trace_id)
