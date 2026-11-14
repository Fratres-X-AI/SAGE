"""Fuzz verify_receipt with arbitrary receipt file bytes."""

from __future__ import annotations

from _common import HMAC_KEY, SCRATCH, VECTORS, expect_typed_rejection, run

from sage.receipt import verify_receipt

TARGET = SCRATCH / "verify.receipt.json"


def test_one_input(data: bytes) -> None:
    TARGET.write_bytes(data)
    expect_typed_rejection(lambda: verify_receipt(TARGET, hmac_key=HMAC_KEY))


def seeds() -> list[bytes]:
    return [p.read_bytes() for p in sorted(VECTORS.glob("kit/*/verify.receipt.json"))]


if __name__ == "__main__":
    run(test_one_input)
