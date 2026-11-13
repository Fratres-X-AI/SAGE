"""The committed conformance vectors (tests/vectors) still match this implementation and the spec."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

VECTORS = Path(__file__).resolve().parent / "vectors"
SAGE_ENV = ("SAGE_PACK_KEY", "SAGE_VERIFY_KEY", "SAGE_WITNESS_KEY", "SAGE_SIGN_PUBLIC_KEY", "SAGE_SIGN_PRIVATE_KEY",
            "SAGE_HANDOFF_KEY", "SAGE_VERIFY_POLICY", "SAGE_REQUIRE_PACK_SIGNATURE")


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"sage_vectors_{name}", VECTORS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_vector_gets_its_expected_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in SAGE_ENV:
        monkeypatch.delenv(name, raising=False)
    assert _load("run_vectors").run(VECTORS) == []


def test_valid_vectors_recompute_from_the_spec_alone() -> None:
    reference = _load("reference_check")
    reference.FAILURES.clear()
    assert reference.main() == 0, reference.FAILURES
