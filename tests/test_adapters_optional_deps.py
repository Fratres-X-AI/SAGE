"""The OpenAI Agents and PydanticAI adapters import without their extras and explain how to install them."""

from __future__ import annotations

import subprocess
import sys

SCRIPT = """
import sys
for name in ("agents", "agents.tracing", "pydantic_ai", "pydantic_ai.models.instrumented",
             "opentelemetry.sdk", "opentelemetry.sdk.trace"):
    sys.modules[name] = None

import sage
import sage.adapters
from sage.adapters import openai_agents, pydantic_ai

assert openai_agents.OPENAI_AGENTS_AVAILABLE is False
assert pydantic_ai.PYDANTIC_AI_AVAILABLE is False
for factory, extra in ((openai_agents.SageOpenAIAgentsProcessor, "[openai-agents]"),
                       (pydantic_ai.SagePydanticAI, "[pydantic-ai]")):
    try:
        factory()
    except ImportError as exc:
        assert extra in str(exc), str(exc)
    else:
        raise AssertionError("expected ImportError")
print("ok")
"""


def test_new_adapters_import_without_their_extras():
    proc = subprocess.run([sys.executable, "-c", SCRIPT], capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "ok"
