"""Fuzz load_policy and apply_policy with arbitrary policy file bytes."""

from __future__ import annotations

from _common import SCRATCH, VECTORS, expect_typed_rejection, run

from sage.policy import apply_policy, load_policy

TARGET = SCRATCH / "policy.json"
REPORT = {"ok": True, "kind": "pack", "sealed": True, "span_count": 4, "redaction_count": 1, "witness_ok": True,
          "pack_hmac_verified": True, "pack_format": "sage.pack.v2", "signature_verified": True}


def test_one_input(data: bytes) -> None:
    TARGET.write_bytes(data)

    def check() -> None:
        policy = load_policy(TARGET)
        policy.digest()
        apply_policy(dict(REPORT), policy)

    expect_typed_rejection(check)


def seeds() -> list[bytes]:
    return [p.read_bytes() for p in sorted((VECTORS / "policy").glob("*.json"))]


if __name__ == "__main__":
    run(test_one_input)
