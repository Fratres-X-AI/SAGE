from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any

from sage.errors import ChainIntegrityError, SplitBrainError
from sage.locks import TraceFileLock
from sage.schema import IncidentBundle, SageSpan

SEQ_ATTR = "sage.seq"
MONO_ATTR = "sage.mono_ns"


@dataclass
class TraceClaim:
    owner: str
    bundle_hash: str
    span_count: int
    claimed_at: float


@dataclass
class TraceRegistry:
    """In-process advisory cache + cross-process file lock for trace_id ownership."""

    _lock: threading.RLock = field(default_factory=threading.RLock)
    _claims: dict[str, TraceClaim] = field(default_factory=dict)
    _active_writers: dict[str, str] = field(default_factory=dict)
    _file_locks: dict[str, TraceFileLock] = field(default_factory=dict)
    lock_root: str | None = None
    use_file_locks: bool = True

    def begin_write(self, trace_id: str, owner: str) -> None:
        # In-process checks under lock; file I/O outside to avoid lock-order deadlocks.
        with self._lock:
            current = self._active_writers.get(trace_id)
            if current is not None and current != owner:
                raise SplitBrainError(
                    f"trace {trace_id} already being written by {current}; refused hijack by {owner}"
                )
            if trace_id in self._claims and self._claims[trace_id].owner != owner:
                raise SplitBrainError(
                    f"trace {trace_id} already finalized by {self._claims[trace_id].owner}"
                )
            need_file = self.use_file_locks and trace_id not in self._file_locks
            self._active_writers[trace_id] = owner
        if need_file:
            flock = TraceFileLock(trace_id, root=self.lock_root, owner=owner)
            try:
                flock.acquire()
            except Exception:
                with self._lock:
                    if self._active_writers.get(trace_id) == owner:
                        self._active_writers.pop(trace_id, None)
                raise
            with self._lock:
                self._file_locks[trace_id] = flock

    def end_write(self, trace_id: str, owner: str) -> None:
        with self._lock:
            if self._active_writers.get(trace_id) == owner:
                self._active_writers.pop(trace_id, None)
            flock = self._file_locks.pop(trace_id, None)
        if flock is not None and flock.owner == owner:
            flock.release()

    def finalize_claim(self, trace_id: str, owner: str, bundle_hash: str, span_count: int) -> None:
        with self._lock:
            prior = self._claims.get(trace_id)
            # Same owner may re-finalize (partial → complete). Different owner = split-brain.
            if prior is not None and prior.owner != owner:
                raise SplitBrainError(
                    f"split-brain finalize for {trace_id}: "
                    f"prior_owner={prior.owner} prior_hash={prior.bundle_hash} "
                    f"new_owner={owner} new_hash={bundle_hash}"
                )
            self._claims[trace_id] = TraceClaim(
                owner=owner,
                bundle_hash=bundle_hash,
                span_count=span_count,
                claimed_at=time.time(),
            )
            self._active_writers.pop(trace_id, None)

    def reset(self) -> None:
        with self._lock:
            for flock in self._file_locks.values():
                flock.release()
            self._file_locks.clear()
            self._claims.clear()
            self._active_writers.clear()


GLOBAL_TRACE_REGISTRY = TraceRegistry()


def stamp_span_order(span: SageSpan, seq: int, mono_ns: int) -> None:
    span.attributes[SEQ_ATTR] = seq
    span.attributes[MONO_ATTR] = mono_ns


def validate_monotonic_chain(bundle: IncidentBundle) -> None:
    """Fail-closed checks for seq uniqueness, parent linking, and parent-before-child."""
    by_id: dict[str, SageSpan] = {s.span_id: s for s in bundle.spans}
    seen_seq: set[int] = set()
    stamped = 0
    for span in bundle.spans:
        seq = span.attributes.get(SEQ_ATTR)
        mono = span.attributes.get(MONO_ATTR)
        if seq is None and mono is None:
            # Legacy bundles without stamps are allowed but cannot claim concurrency safety.
            continue
        stamped += 1
        if not isinstance(seq, int) or seq < 0:
            raise ChainIntegrityError(f"span {span.span_id} has invalid sage.seq={seq!r}")
        if seq in seen_seq:
            raise ChainIntegrityError(f"duplicate sage.seq={seq} on span {span.span_id}")
        seen_seq.add(seq)
        if span.parent_id is not None:
            parent = by_id.get(span.parent_id)
            if parent is None:
                raise ChainIntegrityError(
                    f"broken parent link: {span.span_id} -> {span.parent_id}"
                )
            parent_seq = parent.attributes.get(SEQ_ATTR)
            if isinstance(parent_seq, int) and parent_seq >= seq:
                raise ChainIntegrityError(
                    f"out-of-order parent hashing: child seq={seq} parent seq={parent_seq} "
                    f"span={span.span_id}"
                )
            parent_mono = parent.attributes.get(MONO_ATTR)
            if isinstance(parent_mono, int) and isinstance(mono, int) and parent_mono > mono:
                raise ChainIntegrityError(
                    f"monotonic clock regression: child mono={mono} parent mono={parent_mono}"
                )
    if stamped and stamped != len(bundle.spans):
        raise ChainIntegrityError("partial sage.seq stamps — refuse mixed stamped/unstamped chain")


def detect_ooo_injection(bundle: IncidentBundle, injected: SageSpan) -> None:
    """Reject a span that hijacks the chain with an out-of-order parent/seq."""
    merged = [s.to_dict() for s in bundle.spans if s.span_id != injected.span_id]
    merged.append(injected.to_dict())
    probe = IncidentBundle.from_dict(
        {
            **bundle.to_dict(),
            "audit": {"chain": [], "bundle_hash": ""},
            "spans": merged,
        }
    )
    validate_monotonic_chain(probe)


def concurrent_owner_id() -> str:
    return f"thread-{threading.get_ident()}"
