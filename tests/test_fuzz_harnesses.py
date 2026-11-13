"""Run each fuzz harness on its seeds and a fixed set of mutations, without atheris.

The scheduled fuzz workflow runs the same harnesses under atheris for coverage-guided search.
"""

from __future__ import annotations

import importlib
import random
import sys
from pathlib import Path

import pytest

FUZZ = Path(__file__).resolve().parents[1] / "fuzz"
HARNESSES = ("fuzz_pack", "fuzz_journal", "fuzz_policy", "fuzz_receipt")


def _mutations(seed: bytes, rng: random.Random, count: int) -> list[bytes]:
    out = [b"", b"\x00", b"{}", b"[]", b"null", b'{"format":1}', b"\xff\xfe", seed[: len(seed) // 2]]
    for _ in range(count):
        data = bytearray(seed)
        for _ in range(rng.randint(1, 4)):
            if not data:
                break
            op = rng.randrange(3)
            pos = rng.randrange(len(data))
            if op == 0:
                data[pos] ^= 1 << rng.randrange(8)
            elif op == 1:
                del data[pos : pos + rng.randint(1, 16)]
            else:
                data[pos:pos] = rng.randbytes(rng.randint(1, 8))
        out.append(bytes(data))
    return out


@pytest.mark.parametrize("name", HARNESSES)
def test_harness_holds_typed_rejection_contract(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("SAGE_PACK_KEY", "SAGE_VERIFY_KEY", "SAGE_WITNESS_KEY", "SAGE_SIGN_PUBLIC_KEY", "SAGE_VERIFY_POLICY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.syspath_prepend(str(FUZZ))
    harness = importlib.import_module(name)
    rng = random.Random(f"sage-fuzz-{name}")
    seeds = harness.seeds()
    assert seeds, f"{name} has no seeds"
    for seed in seeds:
        for data in _mutations(seed, rng, 12):
            harness.test_one_input(data)
    sys.modules.pop(name, None)
