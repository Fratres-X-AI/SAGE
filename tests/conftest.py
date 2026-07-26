from __future__ import annotations

import pytest

from sage.concurrency import GLOBAL_TRACE_REGISTRY


@pytest.fixture(autouse=True)
def _reset_trace_registry():
    GLOBAL_TRACE_REGISTRY.reset()
    yield
    GLOBAL_TRACE_REGISTRY.reset()
