"""Fuzz journal verification: replace one file of a valid sealed journal with arbitrary bytes.

Input layout: the first byte picks the file (spans.jsonl, chain.jsonl, manifest.sage.json); the rest
is that file's new content. The other two files keep their valid bytes.
"""

from __future__ import annotations

import shutil

from _common import SCRATCH, VECTORS, expect_typed_rejection, run

from sage.verify import verify_artifact

FILES = ("spans.jsonl", "chain.jsonl", "manifest.sage.json")
SOURCE = VECTORS / "journal" / "valid"
BLOBS = VECTORS / "bundle" / "valid" / "blobs"
ORIGINAL = {name: (SOURCE / name).read_bytes() for name in FILES}
TARGET = SCRATCH / "journal"


def test_one_input(data: bytes) -> None:
    if not data:
        return
    shutil.rmtree(TARGET, ignore_errors=True)
    TARGET.mkdir()
    chosen = FILES[data[0] % len(FILES)]
    for name in FILES:
        (TARGET / name).write_bytes(data[1:] if name == chosen else ORIGINAL[name])
    expect_typed_rejection(lambda: verify_artifact(TARGET, blob_root=BLOBS))


def seeds() -> list[bytes]:
    return [bytes([i]) + ORIGINAL[name] for i, name in enumerate(FILES)]


if __name__ == "__main__":
    run(test_one_input)
