"""The adapter (and the rest of sage) must import when langchain-core is absent."""

from __future__ import annotations

import subprocess
import sys

SCRIPT = """
import sys
for name in ("langchain_core", "langchain_core.callbacks", "langchain_core.callbacks.base"):
    sys.modules[name] = None

import sage
import sage.adapters
import sage.adapters.langchain_callback as lc
from uuid import uuid4

assert lc.LANGCHAIN_AVAILABLE is False
handler = lc.SageLangChainCallback(trace_id="no-lc")
assert handler.raise_error is True and handler.ignore_chain is False
run = uuid4()
handler.on_tool_start(None, "q", run_id=run)
handler.on_tool_end("done", run_id=run)
handler.assert_complete()
assert handler.recorder.bundle.spans[0].outputs == {"output": "done"}
print("ok")
"""


def test_adapter_imports_without_langchain():
    proc = subprocess.run(
        [sys.executable, "-c", SCRIPT], capture_output=True, text=True, timeout=120
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "ok"
