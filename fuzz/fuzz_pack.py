"""Fuzz verify_artifact with arbitrary .sage.tar.gz bytes under the strictest options."""

from __future__ import annotations

from _common import HMAC_KEY, PUBLIC_KEY, SCRATCH, expect_typed_rejection, run

from sage.verify import verify_artifact

TARGET = SCRATCH / "input.sage.tar.gz"


def test_one_input(data: bytes) -> None:
    TARGET.write_bytes(data)
    expect_typed_rejection(
        lambda: verify_artifact(TARGET, hmac_key=HMAC_KEY, public_key=PUBLIC_KEY, require_signature=True,
                                check_witness=True, witness_key=HMAC_KEY)
    )


def seeds() -> list[bytes]:
    from _common import VECTORS

    return [p.read_bytes() for p in sorted((VECTORS / "pack").glob("*.sage.tar.gz"))]


if __name__ == "__main__":
    run(test_one_input)
