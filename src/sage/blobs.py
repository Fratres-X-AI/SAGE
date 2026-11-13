from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import threading
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any, BinaryIO

from sage.errors import BlobIntegrityError, MemoryBudgetExceeded

BLOB_MARKER = "$sage_blob"
DEFAULT_THRESHOLD = 1024  # bytes
DEFAULT_BLOB_ROOT = Path(".sage") / "blobs"
DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB streaming chunks
COMPRESS_THRESHOLD = 64 * 1024  # gzip large blobs
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def require_digest(digest: str) -> str:
    """Fail-closed: CAS addresses must be lowercase hex SHA-256 (no path tricks)."""
    value = str(digest).strip().lower()
    if not DIGEST_RE.fullmatch(value):
        raise BlobIntegrityError(f"invalid CAS digest (expected 64 hex chars): {digest!r}")
    return value

PAYLOAD_KEYS = frozenset(
    {
        "input",
        "output",
        "documents",
        "query",
        "checked_input",
        "context_passed",
        "prompt",
        "content",
        "messages",
        "text",
        "body",
        "context",
        "retrieved",
        "response",
        "request",
    }
)

_store_locks: dict[str, threading.RLock] = {}
_store_locks_guard = threading.Lock()

# Deferred objects hold an open file handle each; bound them per store and per process.
MAX_PENDING_PER_STORE = 64
MAX_PENDING_PER_PROCESS = 256
_pending_handles = 0


def _reserve_pending_handle() -> bool:
    global _pending_handles
    with _store_locks_guard:
        if _pending_handles >= MAX_PENDING_PER_PROCESS:
            return False
        _pending_handles += 1
        return True


def _release_pending_handle() -> None:
    global _pending_handles
    with _store_locks_guard:
        _pending_handles = max(0, _pending_handles - 1)


def default_blob_root() -> Path:
    return Path.cwd() / DEFAULT_BLOB_ROOT


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def _lock_for(root: Path) -> threading.RLock:
    key = str(root.resolve())
    with _store_locks_guard:
        lock = _store_locks.get(key)
        if lock is None:
            lock = threading.RLock()
            _store_locks[key] = lock
        return lock


class MemoryBudget:
    """Stdlib-only peak-resident tracker for streaming CAS writes."""

    def __init__(self, limit_bytes: int | None = None) -> None:
        self.limit_bytes = limit_bytes
        self.peak = 0
        self._current = 0
        self._lock = threading.Lock()

    def charge(self, nbytes: int) -> None:
        with self._lock:
            self._current += nbytes
            if self._current > self.peak:
                self.peak = self._current
            if self.limit_bytes is not None and self._current > self.limit_bytes:
                raise MemoryBudgetExceeded(
                    f"memory budget exceeded: current={self._current} limit={self.limit_bytes}"
                )

    def release(self, nbytes: int) -> None:
        with self._lock:
            self._current = max(0, self._current - nbytes)


class BlobStore:
    """Content-addressable storage under .sage/blobs/<sha256>[.gz]."""

    def __init__(
        self,
        root: str | Path | None = None,
        *,
        memory_budget: MemoryBudget | None = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        compress: bool = True,
    ) -> None:
        self.root = Path(root) if root else default_blob_root()
        self.root.mkdir(parents=True, exist_ok=True)
        self.memory_budget = memory_budget
        self.chunk_size = chunk_size
        self.compress = compress
        self._lock = _lock_for(self.root)
        # Objects written with sync=False: digest -> (temp file, its open handle). They are
        # readable through this store, and get their final name only after an fsync
        # (`sync_pending`). The handle stays open so the fsync and read-backs need no reopen.
        self._pending: dict[str, tuple[Path, Any]] = {}
        self._sync_lock = threading.Lock()

    def __del__(self) -> None:  # pragma: no cover - best-effort handle cleanup
        try:
            for _tmp, handle in list(self._pending.values()):
                handle.close()
                _release_pending_handle()
            self._pending.clear()
        except Exception:
            pass

    def _path_for(self, digest: str, *, gzipped: bool = False) -> Path:
        safe = require_digest(digest)
        path = self.root / (f"{safe}.gz" if gzipped else safe)
        # Defense in depth: resolved path must stay under store root. The name is 64 hex chars
        # directly under the root, so only a symlink planted at that name can point elsewhere;
        # resolving is skipped (it is slow on Windows) unless the entry is a link.
        if os.path.islink(path):
            root = self.root.resolve()
            resolved = path.resolve()
            if root not in resolved.parents and resolved != root:
                raise BlobIntegrityError(f"CAS path escape blocked for digest={digest!r}")
        return path

    def _resolve_path(self, digest: str) -> Path:
        safe = require_digest(digest)
        plain = self._path_for(safe, gzipped=False)
        gz = self._path_for(safe, gzipped=True)
        if plain.exists():
            return plain
        if gz.exists():
            return gz
        pending = self._pending.get(safe)
        if pending is not None:
            return pending[0]
        raise FileNotFoundError(f"missing blob {safe} under {self.root}")

    def put_bytes(self, data: bytes, *, sync: bool = True) -> str:
        """Store bytes. With ``sync=False`` a small object is fsynced later (``sync_pending``).

        A deferred object keeps a temp name, readable only through this store instance, until
        ``sync_pending()`` runs. An object never gets its final name before it has been fsynced.
        """
        # Dedup fast path: the payload is already in memory, so hash it first and skip the temp
        # file (write + fsync) when the object exists. The existing object is still re-verified.
        if data:
            digest = hashlib.sha256(data).hexdigest()
            with self._lock:
                present = self.exists(digest)
            if present:
                if self.memory_budget is not None:
                    self.memory_budget.charge(len(data))
                    self.memory_budget.release(len(data))
                try:
                    self.verify_blob(digest)
                    if sync and digest in self._pending:
                        self.sync_pending()
                    return digest
                except FileNotFoundError:
                    pass  # removed between the check and the verify; write it again
            if not sync and len(data) < COMPRESS_THRESHOLD:
                return self._put_deferred(data, digest)
        return self.put_stream([data], expected_size=len(data))

    def _put_deferred(self, data: bytes, digest: str) -> str:
        if len(self._pending) >= MAX_PENDING_PER_STORE:
            self.sync_pending()
        if not _reserve_pending_handle():
            return self.put_stream([data], expected_size=len(data))
        if self.memory_budget is not None:
            self.memory_budget.charge(len(data))
            self.memory_budget.release(len(data))
        tmp_fd, tmp_name = _mktemp(self.root)
        handle = os.fdopen(tmp_fd, "w+b")
        try:
            handle.write(data)
            handle.flush()
            # Fail-closed: read the object back and re-hash it before returning the address.
            handle.seek(0)
            if hashlib.sha256(handle.read()).hexdigest() != digest:
                raise BlobIntegrityError(f"blob mutation detected: address={digest} read-back mismatch")
            with self._lock:
                duplicate = digest in self._pending or (
                    self._path_for(digest).exists() or self._path_for(digest, gzipped=True).exists()
                )
                if not duplicate:
                    self._pending[digest] = (Path(tmp_name), handle)
        except BaseException:
            handle.close()
            _release_pending_handle()
            Path(tmp_name).unlink(missing_ok=True)
            raise
        if duplicate:  # another thread stored it first
            handle.close()
            _release_pending_handle()
            Path(tmp_name).unlink(missing_ok=True)
            self.verify_blob(digest)
        return digest

    def sync_pending(self) -> int:
        """Fsync every object written with ``sync=False`` and give it its final name."""
        with self._sync_lock:
            with self._lock:
                items = list(self._pending.items())
            for digest, (tmp, handle) in items:
                os.fsync(handle.fileno())
                with self._lock:
                    handle.close()  # Windows cannot rename an open file
                    self._pending.pop(digest, None)
                    _release_pending_handle()
                    if self._path_for(digest).exists() or self._path_for(digest, gzipped=True).exists():
                        tmp.unlink(missing_ok=True)
                    else:
                        _atomic_replace(tmp, self._path_for(digest))
            return len(items)

    def put_stream(
        self,
        chunks: Iterable[bytes],
        *,
        expected_size: int | None = None,
        force_compress: bool | None = None,
    ) -> str:
        """Stream chunks to a temp file, hash, atomic-rename, verify-after-write."""
        hasher = hashlib.sha256()
        tmp_fd, tmp_name = _mktemp(self.root)
        written = 0
        try:
            with os.fdopen(tmp_fd, "wb") as handle:
                for chunk in chunks:
                    if not chunk:
                        continue
                    if self.memory_budget is not None:
                        self.memory_budget.charge(len(chunk))
                    try:
                        hasher.update(chunk)
                        handle.write(chunk)
                        written += len(chunk)
                    finally:
                        if self.memory_budget is not None:
                            self.memory_budget.release(len(chunk))
                handle.flush()
                os.fsync(handle.fileno())
            digest = hasher.hexdigest()
            use_gz = (
                force_compress
                if force_compress is not None
                else (self.compress and written >= COMPRESS_THRESHOLD)
            )
            final = self._path_for(digest, gzipped=use_gz)
            with self._lock:
                if final.exists():
                    # Dedup path: verify existing object, drop temp.
                    self.verify_blob(digest)
                    Path(tmp_name).unlink(missing_ok=True)
                    return digest
                if use_gz:
                    _atomic_gzip_replace(Path(tmp_name), final)
                else:
                    _atomic_replace(Path(tmp_name), final)
                # Fail-closed: re-hash from disk before returning the address.
                self.verify_blob(digest)
            if expected_size is not None and written != expected_size:
                raise BlobIntegrityError(
                    f"stream size mismatch: wrote={written} expected={expected_size}"
                )
            return digest
        except Exception:
            Path(tmp_name).unlink(missing_ok=True)
            raise

    def put_text(self, text: str, *, sync: bool = True) -> str:
        # Stream encode in chunks to avoid a second full copy when possible.
        raw = text.encode("utf-8")
        return self.put_bytes(raw, sync=sync)

    def put_text_streaming(self, text: str) -> str:
        """Hash/write a large string in chunk_size windows without holding dual copies of slices long-term."""
        encoded = memoryview(text.encode("utf-8"))
        size = len(encoded)

        def _iter() -> Iterator[bytes]:
            offset = 0
            while offset < size:
                end = min(offset + self.chunk_size, size)
                yield bytes(encoded[offset:end])
                offset = end

        return self.put_stream(_iter(), expected_size=size)

    def put_json(self, value: Any, *, sync: bool = True) -> str:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return self.put_text(payload, sync=sync)

    def iter_bytes(self, digest: str, *, chunk_size: int | None = None) -> Iterator[bytes]:
        """Yield verified-path bytes in chunks (stdlib gzip/file streaming)."""
        size = chunk_size or self.chunk_size
        pending_data: bytes | None = None
        with self._lock:
            path = self._resolve_path(digest)
            entry = self._pending.get(digest)
            if entry is not None and entry[0] == path:
                # Read under the lock, through the retained handle: `sync_pending` closes and
                # renames this file. Pending objects are small (below 64 KiB).
                try:
                    entry[1].seek(0)
                    pending_data = entry[1].read()
                except Exception as exc:
                    raise BlobIntegrityError(
                        f"blob mutation/corruption detected for {digest}: {exc}"
                    ) from exc
        if pending_data is not None:
            for offset in range(0, len(pending_data), size):
                block = pending_data[offset : offset + size]
                if self.memory_budget is not None:
                    self.memory_budget.charge(len(block))
                try:
                    yield block
                finally:
                    if self.memory_budget is not None:
                        self.memory_budget.release(len(block))
            return
        try:
            if path.suffix == ".gz":
                with gzip.open(path, "rb") as handle:
                    while True:
                        block = handle.read(size)
                        if not block:
                            break
                        if self.memory_budget is not None:
                            self.memory_budget.charge(len(block))
                        try:
                            yield block
                        finally:
                            if self.memory_budget is not None:
                                self.memory_budget.release(len(block))
            else:
                with path.open("rb") as handle:
                    while True:
                        block = handle.read(size)
                        if not block:
                            break
                        if self.memory_budget is not None:
                            self.memory_budget.charge(len(block))
                        try:
                            yield block
                        finally:
                            if self.memory_budget is not None:
                                self.memory_budget.release(len(block))
        except BlobIntegrityError:
            raise
        except Exception as exc:
            raise BlobIntegrityError(
                f"blob mutation/corruption detected for {digest}: {exc}"
            ) from exc

    def verify_blob_streaming(self, digest: str) -> int:
        """Hash-on-read without retaining the full payload in memory."""
        hasher = hashlib.sha256()
        total = 0
        for block in self.iter_bytes(digest):
            hasher.update(block)
            total += len(block)
        actual = hasher.hexdigest()
        if actual != digest:
            raise BlobIntegrityError(
                f"blob mutation detected (streaming): address={digest} actual={actual}"
            )
        return total

    def get_bytes(self, digest: str, *, verify: bool = True) -> bytes:
        """Single-pass read: hash while materializing (no double disk scan)."""
        hasher = hashlib.sha256()
        parts: list[bytes] = []
        for block in self.iter_bytes(digest):
            if verify:
                hasher.update(block)
            parts.append(block)
        data = b"".join(parts)
        if verify:
            actual = hasher.hexdigest()
            if actual != digest:
                raise BlobIntegrityError(
                    f"blob mutation detected: address={digest} actual={actual}"
                )
        return data

    def verify_blob(self, digest: str) -> None:
        self.verify_blob_streaming(digest)

    def get_text(self, digest: str, *, verify: bool = True) -> str:
        return self.get_bytes(digest, verify=verify).decode("utf-8")

    def get_json(self, digest: str, *, verify: bool = True) -> Any:
        return json.loads(self.get_text(digest, verify=verify))

    def exists(self, digest: str) -> bool:
        return (
            self._path_for(digest).exists()
            or self._path_for(digest, gzipped=True).exists()
            or require_digest(digest) in self._pending
        )

    def open_verified(self, digest: str) -> bytes:
        """Alias used by replay rehydration (always verifies)."""
        return self.get_bytes(digest, verify=True)


def _mktemp(root: Path) -> tuple[int, str]:
    root.mkdir(parents=True, exist_ok=True)
    return tempfile_mkstemp(root)


def tempfile_mkstemp(root: Path) -> tuple[int, str]:
    import tempfile

    return tempfile.mkstemp(prefix=".sage-blob-", dir=str(root))


def _atomic_replace(src: Path, dst: Path) -> None:
    os.replace(str(src), str(dst))


def _atomic_gzip_replace(src: Path, dst: Path) -> None:
    tmp_gz = dst.with_suffix(dst.suffix + ".partial")
    with src.open("rb") as fin, gzip.open(tmp_gz, "wb", compresslevel=6) as fout:
        while True:
            block = fin.read(DEFAULT_CHUNK_SIZE)
            if not block:
                break
            fout.write(block)
        fout.flush()
        os.fsync(fout.fileno())
    src.unlink(missing_ok=True)
    os.replace(str(tmp_gz), str(dst))


class DeferredSyncStore:
    """Write-only view of a ``BlobStore`` whose small objects are fsynced later, in one group.

    The recorder offloads through this view when the journal durability is ``batch`` or ``close``;
    the journal writer calls ``BlobStore.sync_pending()`` before it commits the spans that refer
    to those objects, so an object is always durable before a journal line names it.
    """

    def __init__(self, store: BlobStore) -> None:
        self._store = store
        self.root = store.root
        self.chunk_size = store.chunk_size

    def put_text(self, text: str) -> str:
        return self._store.put_text(text, sync=False)

    def put_text_streaming(self, text: str) -> str:
        return self._store.put_text_streaming(text)

    def put_json(self, value: Any) -> str:
        return self._store.put_json(value, sync=False)


def is_blob_ref(value: Any) -> bool:
    return isinstance(value, dict) and BLOB_MARKER in value


def make_blob_ref(digest: str, *, size: int | None = None) -> dict[str, Any]:
    ref: dict[str, Any] = {BLOB_MARKER: require_digest(digest)}
    if size is not None:
        ref["size"] = size
    return ref


def _utf8_size(value: Any) -> int:
    if isinstance(value, str):
        return len(value.encode("utf-8"))
    if isinstance(value, (bytes, bytearray)):
        return len(value)
    try:
        return len(
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        )
    except TypeError:
        return 0


def offload_value(
    value: Any,
    store: BlobStore,
    *,
    threshold: int = DEFAULT_THRESHOLD,
    allow_container_offload: bool = True,
    memo: dict[Any, dict[str, Any]] | None = None,
) -> Any:
    """Replace large payloads with CAS references.

    ``memo`` (one per span) reuses the reference when the same payload occurs again, as it does
    when ``data.input`` mirrors ``inputs``; the object is then written and verified once.
    """
    if is_blob_ref(value):
        return value
    if isinstance(value, str):
        raw_size = len(value.encode("utf-8"))
        if raw_size >= threshold:
            key = ("text", value)
            if memo is not None and key in memo:
                return dict(memo[key])
            if raw_size >= store.chunk_size:
                digest = store.put_text_streaming(value)
            else:
                digest = store.put_text(value)
            ref = make_blob_ref(digest, size=raw_size)
            if memo is not None:
                memo[key] = dict(ref)
            return ref
        return value
    if isinstance(value, dict):
        payload, size = _canonical_payload(value)
        if allow_container_offload and size >= threshold and not any(str(k).startswith("$") for k in value):
            return _offload_container(value, payload, size, store, memo)
        return {
            key: offload_value(
                child,
                store,
                threshold=threshold,
                allow_container_offload=str(key) in PAYLOAD_KEYS or not isinstance(child, dict),
                memo=memo,
            )
            for key, child in value.items()
        }
    if isinstance(value, list):
        payload, size = _canonical_payload(value)
        if allow_container_offload and size >= threshold:
            return _offload_container(value, payload, size, store, memo)
        return [
            offload_value(child, store, threshold=threshold, allow_container_offload=True, memo=memo)
            for child in value
        ]
    return value


def _canonical_payload(value: Any) -> tuple[str | None, int]:
    """Canonical JSON text and its UTF-8 size (`(None, 0)` when the value is not serializable)."""
    try:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except TypeError:
        return None, 0
    return payload, len(payload.encode("utf-8"))


def _offload_container(
    value: Any,
    payload: str | None,
    size: int,
    store: BlobStore,
    memo: dict[Any, dict[str, Any]] | None,
) -> dict[str, Any]:
    key = ("json", payload)
    if memo is not None and payload is not None and key in memo:
        return dict(memo[key])
    # The canonical text is what `put_json` would serialize; store it without a second dump.
    digest = store.put_text(payload) if payload is not None else store.put_json(value)
    ref = make_blob_ref(digest, size=size)
    if memo is not None and payload is not None:
        memo[key] = dict(ref)
    return ref


def rehydrate_value(value: Any, store: BlobStore) -> Any:
    """Resolve blob refs; hard-fail on digest mismatch (BlobIntegrityError)."""
    if is_blob_ref(value):
        digest = require_digest(str(value[BLOB_MARKER]))
        text = store.get_text(digest, verify=True)
        if value.get("size") is not None and len(text.encode("utf-8")) != int(value["size"]):
            raise BlobIntegrityError(
                f"blob size mismatch for {digest}: claimed={value['size']} actual={len(text.encode('utf-8'))}"
            )
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text
    if isinstance(value, dict):
        return {key: rehydrate_value(child, store) for key, child in value.items()}
    if isinstance(value, list):
        return [rehydrate_value(child, store) for child in value]
    return value


def offload_bundle(
    bundle_dict: dict[str, Any],
    store: BlobStore,
    *,
    threshold: int = DEFAULT_THRESHOLD,
) -> dict[str, Any]:
    clone = json.loads(json.dumps(bundle_dict))
    for span in clone.get("spans") or []:
        for field in ("inputs", "outputs", "attributes"):
            if isinstance(span.get(field), dict):
                span[field] = {
                    key: offload_value(child, store, threshold=threshold, allow_container_offload=True)
                    for key, child in span[field].items()
                }
        data = span.get("data")
        if isinstance(data, dict):
            span["data"] = {
                key: offload_value(
                    child,
                    store,
                    threshold=threshold,
                    allow_container_offload=str(key) in PAYLOAD_KEYS and not isinstance(child, dict),
                )
                for key, child in data.items()
            }
    meta = dict(clone.get("metadata") or {})
    meta["blob_store"] = str(store.root)
    meta["blob_threshold"] = threshold
    clone["metadata"] = meta
    return clone


def rehydrate_bundle_dict(
    data: dict[str, Any],
    store: BlobStore | None = None,
) -> dict[str, Any]:
    if store is None:
        meta = data.get("metadata") or {}
        root = meta.get("blob_store")
        store = BlobStore(root) if root else BlobStore()
    clone = json.loads(json.dumps(data))
    for span in clone.get("spans") or []:
        for field in ("inputs", "outputs", "attributes", "data"):
            if field in span:
                span[field] = rehydrate_value(span[field], store)
    return clone


def offload_span(span: Any, store: BlobStore, *, threshold: int = DEFAULT_THRESHOLD) -> Any:
    """CAS-offload the large payloads of one span in place."""
    memo: dict[Any, dict[str, Any]] = {}
    span.inputs = {
        key: offload_value(child, store, threshold=threshold, allow_container_offload=True, memo=memo)
        for key, child in (span.inputs or {}).items()
    }
    span.outputs = {
        key: offload_value(child, store, threshold=threshold, allow_container_offload=True, memo=memo)
        for key, child in (span.outputs or {}).items()
    }
    span.attributes = {
        key: offload_value(child, store, threshold=threshold, allow_container_offload=True, memo=memo)
        for key, child in (span.attributes or {}).items()
    }
    data = span.data or {}
    span.data = {
        key: offload_value(
            child,
            store,
            threshold=threshold,
            allow_container_offload=str(key) in PAYLOAD_KEYS and not isinstance(child, dict),
            memo=memo,
        )
        for key, child in data.items()
    }
    if getattr(span, "events", None):
        span.events = [
            offload_value(ev, store, threshold=threshold, allow_container_offload=True, memo=memo)
            if isinstance(ev, dict)
            else ev
            for ev in span.events
        ]
    return span


def apply_offload_to_incident(
    bundle: Any,
    store: BlobStore,
    *,
    threshold: int = DEFAULT_THRESHOLD,
) -> Any:
    for span in bundle.spans:
        offload_span(span, store, threshold=threshold)
    meta = dict(bundle.metadata or {})
    meta["blob_store"] = str(store.root)
    meta["blob_threshold"] = threshold
    bundle.metadata = meta
    return bundle


# Silence unused BinaryIO import warning path for type checkers using streaming APIs.
_ = BinaryIO
