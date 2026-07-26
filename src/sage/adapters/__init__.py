"""Framework adapters. Core stays stdlib-only; adapters are optional integration points."""

from sage.adapters.langchain_callback import SageLangChainCallback, attach_langchain_callback
from sage.adapters.otel_tap import OpenTelemetryTap, attach_otel_tap
from sage.adapters.run_wrapper import autogen_chat, crewai_kickoff, wrap_agent_run

__all__ = [
    "OpenTelemetryTap",
    "SageLangChainCallback",
    "attach_langchain_callback",
    "attach_otel_tap",
    "autogen_chat",
    "crewai_kickoff",
    "wrap_agent_run",
]
