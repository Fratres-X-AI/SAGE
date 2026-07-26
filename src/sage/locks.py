from __future__ import annotations

import json
import os
import time
from pathlib import Path

from sage.errors import SplitBrainError

DEFAULT_LOCK_ROOT = Path(".sage") / "locks"


class TraceFileLock:
    """Cross-process exclusive ownership for a trace_id via O_EXCL lockfile + pid claim.

    The lockfile is created exclusively then closed immediately so Windows does not
    retain a mandatory byte-range lock on an open fd across threads/tests.
    """

    def __init__(
        self,
        trace_id: str,
        *,
        root: str | Path | None = None,
        owner: str | None = None,
        stale_seconds: float = 3600.0,
    ) -> None:
        self.trace_id = trace_id
        self.root = Path(root) if root else Path.cwd() / DEFAULT_LOCK_ROOT
        self.root.mkdir(parents=True, exist_ok=True)
        safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in trace_id)
        self.path = self.root / f"{safe}.lock"
        self.owner = owner or f"pid-{os.getpid()}-{time.time_ns()}"
        self.stale_seconds = stale_seconds
        self._held = False

    def acquire(self, *, blocking: bool = False, timeout: float = 0.0) -> None:
        deadline = time.monotonic() + timeout if timeout else None
        while True:
            try:
                self._try_acquire()
                return
            except SplitBrainError:
                if blocking and (deadline is None or time.monotonic() < deadline):
                    time.sleep(0.01)
                    continue
                raise

    def _try_acquire(self) -> None:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        try:
            fd = os.open(str(self.path), flags, 0o644)
        except FileExistsError:
            self._reclaim_or_reject()
            fd = os.open(str(self.path), flags, 0o644)
        payload = {
            "trace_id": self.trace_id,
            "owner": self.owner,
            "pid": os.getpid(),
            "acquired_at": time.time(),
        }
        try:
            os.write(fd, json.dumps(payload).encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        self._held = True

    def _reclaim_or_reject(self) -> None:
        try:
            raw = self.path.read_text(encoding="utf-8")
            data = json.loads(raw) if raw.strip() else {}
        except (OSError, json.JSONDecodeError):
            data = {}
        owner = data.get("owner")
        pid = data.get("pid")
        acquired_at = float(data.get("acquired_at") or 0)
        if owner == self.owner:
            try:
                self.path.unlink()
            except OSError:
                pass
            return
        stale = acquired_at and (time.time() - acquired_at > self.stale_seconds)
        dead = False
        if isinstance(pid, int) and pid > 0:
            dead = not _pid_alive(pid)
        if stale or dead:
            try:
                self.path.unlink()
                return
            except OSError as exc:
                raise SplitBrainError(
                    f"trace {self.trace_id} lock busy (stale reclaim failed): {exc}"
                ) from exc
        raise SplitBrainError(
            f"trace {self.trace_id} locked by {owner!r} pid={pid}; refused hijack by {self.owner}"
        )

    def release(self) -> None:
        if not self._held:
            return
        self._held = False
        try:
            if not self.path.exists():
                return
            raw = self.path.read_text(encoding="utf-8")
            data = json.loads(raw) if raw.strip() else {}
            if data.get("owner") in {None, self.owner}:
                self.path.unlink()
        except (OSError, json.JSONDecodeError):
            try:
                self.path.unlink()
            except OSError:
                pass

    def __enter__(self) -> "TraceFileLock":
        self.acquire()
        return self

    def __exit__(self, *args: object) -> None:
        self.release()


def _pid_alive(pid: int) -> bool:
    if os.name == "nt":
        # Best-effort on Windows without holding native handles.
        try:
            import ctypes

            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = ctypes.windll.kernel32.OpenProcess(  # type: ignore[attr-defined]
                PROCESS_QUERY_LIMITED_INFORMATION, 0, pid
            )
            if handle:
                ctypes.windll.kernel32.CloseHandle(handle)  # type: ignore[attr-defined]
                return True
            return False
        except Exception:
            return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True
    return True
