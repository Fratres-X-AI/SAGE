"""Write each harness's seed inputs to fuzz/corpus/<harness>/ for libFuzzer.

    python fuzz/write_corpus.py
"""

from __future__ import annotations

import hashlib
import importlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESSES = ("fuzz_pack", "fuzz_journal", "fuzz_policy", "fuzz_receipt")


def main() -> int:
    sys.path.insert(0, str(HERE))
    for name in HARNESSES:
        out = HERE / "corpus" / name
        out.mkdir(parents=True, exist_ok=True)
        seeds = importlib.import_module(name).seeds()
        for seed in seeds:
            (out / hashlib.sha256(seed).hexdigest()[:16]).write_bytes(seed)
        print(f"{name}: {len(seeds)} seeds -> {out.relative_to(HERE.parent).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
