from __future__ import annotations

import hashlib
from typing import Iterable, Sequence


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def merkle_root(leaves: Sequence[str]) -> str:
    """Binary Merkle root over hex leaf digests (SHA-256 of concatenated child hex).

    Empty → 64 zero hex. Odd levels duplicate the last node (Bitcoin-style).
    """
    if not leaves:
        return "0" * 64
    level = [leaf.lower() for leaf in leaves]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        nxt: list[str] = []
        for i in range(0, len(level), 2):
            paired = (level[i] + level[i + 1]).encode("utf-8")
            nxt.append(_sha256_hex(paired))
        level = nxt
    return level[0]


def chain_merkle_root(chain: Iterable[dict]) -> str:
    leaves = [str(link.get("hash") or "") for link in chain]
    leaves = [h for h in leaves if h]
    return merkle_root(leaves)
