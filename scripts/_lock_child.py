from __future__ import annotations

import sys

from sage.errors import SplitBrainError
from sage.locks import TraceFileLock


def main() -> int:
    trace_id = sys.argv[1]
    lock_root = sys.argv[2]
    lock = TraceFileLock(trace_id, root=lock_root, owner="child")
    try:
        lock.acquire()
    except SplitBrainError as exc:
        print(f"split:{exc}")
        return 2
    print("acquired")
    lock.release()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
