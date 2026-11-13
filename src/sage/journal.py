from __future__ import annotations

import atexit
import copy
import json
import os
import tempfile
import threading
import time
import weakref
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from sage.audit import (
    build_audit_chain,
    compute_bundle_hash,
    order_spans,
    redact_value,
    require_normal_form,
    require_verified,
    sha256_digest,
)
from sage.blobs import BlobStore, DEFAULT_THRESHOLD, DeferredSyncStore, offload_span
from sage.errors import ChainIntegrityError, FaultRecoveryError, JournalWriteError, SageError
from sage.locks import read_text_file, replace_file
from sage.fault import CrashBoundary, RecoveryReport
from sage.schema import AuditBlock, BundleSource, IncidentBundle, SCHEMA_VERSION, SageSpan, utc_now

SPANS_JSONL = "spans.jsonl"
CHAIN_JSONL = "chain.jsonl"
MANIFEST_NAME = "manifest.sage.json"
MANIFEST_WAL = "manifest.wal.jsonl"
ZERO_HASH = "0" * 64

# Live-journal durability modes (see README "Live journal durability").
DURABILITY_SPAN = "span"  # fsync every closed span before end_span returns
DURABILITY_BATCH = "batch"  # group commit (fsync) from a background writer thread
DURABILITY_CLOSE = "close"  # background writes, fsync only at flush / seal
DURABILITY_MODES = (DURABILITY_SPAN, DURABILITY_BATCH, DURABILITY_CLOSE)
DEFAULT_DURABILITY = DURABILITY_BATCH
DURABILITY_ENV = "SAGE_JOURNAL_DURABILITY"
# A group commit starts when the oldest uncommitted span is this old, or this many spans wait.
DEFAULT_BATCH_INTERVAL_MS = 50
DEFAULT_BATCH_MAX_SPANS = 256
# Hard bound: end_span blocks once this many batches' worth of spans are uncommitted.
MAX_UNCOMMITTED_BATCHES = 4
_WRITER_IDLE_EXIT_S = 0.5
_LINESEP = os.linesep.encode("ascii")


def resolve_durability(mode: str | None = None) -> str:
    """Validate a durability mode. `None` means `$SAGE_JOURNAL_DURABILITY`, then the default."""
    chosen = mode if mode is not None else (os.environ.get(DURABILITY_ENV) or DEFAULT_DURABILITY)
    chosen = str(chosen).strip().lower()
    if chosen not in DURABILITY_MODES:
        raise ValueError(
            f"unknown journal durability {chosen!r}; expected one of {', '.join(DURABILITY_MODES)}"
        )
    return chosen


@dataclass
class JournalPaths:
    directory: Path

    @property
    def spans(self) -> Path:
        return self.directory / SPANS_JSONL

    @property
    def chain(self) -> Path:
        return self.directory / CHAIN_JSONL

    @property
    def manifest(self) -> Path:
        return self.directory / MANIFEST_NAME

    @property
    def wal(self) -> Path:
        return self.directory / MANIFEST_WAL


def is_journal_dir(path: str | Path) -> bool:
    p = Path(path)
    return p.is_dir() and (p / MANIFEST_NAME).exists() and (p / SPANS_JSONL).exists()


def is_journal_path(path: str | Path) -> bool:
    p = Path(path)
    if p.is_dir():
        return is_journal_dir(p)
    if p.name in {MANIFEST_NAME, SPANS_JSONL, CHAIN_JSONL}:
        return is_journal_dir(p.parent)
    return False


def journal_root(path: str | Path) -> Path:
    p = Path(path)
    if p.is_dir():
        return p
    return p.parent


def span_content_hash(span: SageSpan) -> str:
    return sha256_digest(span.to_dict())


def manifest_seal_payload(manifest: dict[str, Any]) -> dict[str, Any]:
    body = {k: v for k, v in manifest.items() if k != "manifest_seal"}
    return body


def compute_manifest_seal(manifest: dict[str, Any]) -> str:
    return sha256_digest(manifest_seal_payload(manifest))


def verify_manifest_seal(manifest: dict[str, Any]) -> None:
    seal = manifest.get("manifest_seal")
    if not seal:
        raise ChainIntegrityError("manifest missing manifest_seal")
    expected = compute_manifest_seal(manifest)
    if seal != expected:
        raise ChainIntegrityError(
            f"manifest_seal mismatch: claimed={seal!r} expected={expected!r}"
        )


def prepare_span_for_disk(
    span: SageSpan,
    *,
    blob_store: BlobStore | None = None,
    redaction_policy: dict[str, Any] | None = None,
    blob_threshold: int = DEFAULT_THRESHOLD,
    blob_sync: bool = True,
) -> SageSpan:
    """Redact secrets and CAS-offload large payloads before any journal append.

    With ``blob_sync=False`` offloaded objects are fsynced later by ``BlobStore.sync_pending()``.
    """
    from sage.audit import redact_span, resolve_redaction_rules

    # No deep copy: `redact_span` rebuilds every container the clone holds, so the clone never
    # shares a mutable container with the caller's span.
    clone = SageSpan.from_dict(span.to_dict())
    fragments, patterns = resolve_redaction_rules(redaction_policy)
    redact_span(clone, key_fragments=fragments, value_patterns=patterns)

    if blob_store is not None:
        target = blob_store if blob_sync else DeferredSyncStore(blob_store)
        offload_span(clone, target, threshold=blob_threshold)  # type: ignore[arg-type]
    return clone


def apply_sanitized_fields(target: SageSpan, prepared: SageSpan) -> None:
    """Copy redact/CAS fields onto the in-memory span (secrets leave the process heap)."""
    target.inputs = prepared.inputs
    target.outputs = prepared.outputs
    target.attributes = prepared.attributes
    target.data = prepared.data
    target.events = prepared.events
    target.name = prepared.name
    target.failure_context = prepared.failure_context
    target.error = prepared.error


def sanitize_span_inplace(
    span: SageSpan,
    *,
    blob_store: BlobStore | None = None,
    redaction_policy: dict[str, Any] | None = None,
    blob_threshold: int = DEFAULT_THRESHOLD,
) -> SageSpan:
    prepared = prepare_span_for_disk(
        span,
        blob_store=blob_store,
        redaction_policy=redaction_policy,
        blob_threshold=blob_threshold,
    )
    apply_sanitized_fields(span, prepared)
    return span


def lookup_content_hash_from_chain(directory: str | Path, span_id: str) -> str | None:
    path = Path(directory) / CHAIN_JSONL
    if not path.exists() or not span_id:
        return None
    objects, _ = load_jsonl_objects(path)
    for link in objects:
        if link.get("span_id") == span_id:
            return str(link.get("content_hash") or link.get("span_hash") or "") or None
    return None


def make_chain_link(
    span: SageSpan,
    *,
    index: int,
    prev_hash: str,
    content_by_id: dict[str, str] | None = None,
) -> dict[str, Any]:
    content = content_by_id or {}
    content_hash = content.get(span.span_id) or span_content_hash(span)
    parent_hash = content.get(span.parent_id) if span.parent_id else None
    record = {
        "index": index,
        "span_id": span.span_id,
        "span_type": span.type,
        "span_name": span.name,
        "timestamp": span.end_time or span.start_time or "",
        "prev_hash": prev_hash,
        "span_hash": content_hash,
        "content_hash": content_hash,
        "parent_id": span.parent_id,
        "parent_content_hash": parent_hash,
    }
    record["hash"] = sha256_digest(record)
    return record


def enrich_audit_chain(bundle: IncidentBundle) -> list[dict[str, Any]]:
    return build_audit_chain(bundle)


def attach_enriched_audit(bundle: IncidentBundle) -> IncidentBundle:
    order_spans(bundle)
    chain = build_audit_chain(bundle)
    bundle.audit = AuditBlock(chain=chain, bundle_hash="")
    bundle.audit.bundle_hash = compute_bundle_hash(bundle)
    return bundle


def _atomic_write_text(path: Path, text: str, *, fsync: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".sage-w-", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            if fsync:
                os.fsync(handle.fileno())
        replace_file(tmp, str(path))
    except Exception:
        Path(tmp).unlink(missing_ok=True)
        raise


def save_journal(bundle: IncidentBundle, directory: str | Path) -> JournalPaths:
    """Persist journal: spans.jsonl + chain.jsonl + sealed manifest.sage.json."""
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    paths = JournalPaths(root)

    bundle.metadata = {
        **bundle.metadata,
        "storage": "sage.journal.v1",
        "spans_file": SPANS_JSONL,
        "chain_file": CHAIN_JSONL,
    }
    # Drop live flag on seal.
    bundle.metadata.pop("live_recording", None)
    working = attach_enriched_audit(bundle)

    fd, tmp = tempfile.mkstemp(prefix=".spans-", suffix=".jsonl", dir=str(root))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for span in working.spans:
                handle.write(json.dumps(span.to_dict(), sort_keys=True, separators=(",", ":")))
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        replace_file(tmp, str(paths.spans))
    except Exception:
        Path(tmp).unlink(missing_ok=True)
        raise

    c_fd, c_tmp = tempfile.mkstemp(prefix=".chain-", suffix=".jsonl", dir=str(root))
    try:
        with os.fdopen(c_fd, "w", encoding="utf-8") as handle:
            for link in working.audit.chain:
                handle.write(json.dumps(link, sort_keys=True, separators=(",", ":")))
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        replace_file(c_tmp, str(paths.chain))
    except Exception:
        Path(c_tmp).unlink(missing_ok=True)
        raise

    from sage.merkle import chain_merkle_root

    tip = working.audit.chain[-1]["hash"] if working.audit.chain else ZERO_HASH
    merkle = chain_merkle_root(working.audit.chain)
    manifest = {
        "schema_version": working.schema_version,
        "bundle_id": working.bundle_id,
        "title": working.title,
        "created_at": working.created_at,
        "source": working.source.to_dict(),
        "status": working.status,
        "root_cause_hint": working.root_cause_hint,
        "metadata": working.metadata,
        "redactions": working.redactions,
        "redaction_policy": working.redaction_policy,
        "audit": working.audit.to_dict(),
        "span_count": len(working.spans),
        "span_ids": [s.span_id for s in working.spans],
        "chain_tip": tip,
        "merkle_root": merkle,
        "chain_file": CHAIN_JSONL,
        "spans_file": SPANS_JSONL,
    }
    manifest["manifest_seal"] = compute_manifest_seal(manifest)
    _atomic_write_text(paths.manifest, json.dumps(manifest, indent=2, sort_keys=True))
    return paths


def append_jsonl_line(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())


def append_span_line(directory: str | Path, span: SageSpan) -> None:
    append_jsonl_line(Path(directory) / SPANS_JSONL, span.to_dict())


def append_chain_link(directory: str | Path, link: dict[str, Any]) -> None:
    append_jsonl_line(Path(directory) / CHAIN_JSONL, link)


def _jsonl_line(obj: dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def encode_span_record(span: SageSpan) -> tuple[str, str]:
    """Return `(content_hash, spans.jsonl line)` for a span from one serialization where possible.

    The content hash is over canonical JSON (`ensure_ascii=False`); the journal line is the same
    JSON with `ensure_ascii=True`. The two texts are identical when the canonical form is pure
    ASCII, which is the common case, so the span is serialized once instead of twice.
    """
    import hashlib

    payload = span.to_dict()
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    content_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    line = canonical if canonical.isascii() else _jsonl_line(payload)
    return content_hash, line


def append_live_span(
    directory: str | Path,
    span: SageSpan,
    *,
    index: int,
    prev_hash: str,
    blob_store: BlobStore | None = None,
    redaction_policy: dict[str, Any] | None = None,
    blob_threshold: int = DEFAULT_THRESHOLD,
    content_by_id: dict[str, str] | None = None,
    disk_span: SageSpan | None = None,
) -> tuple[SageSpan, dict[str, Any]]:
    """Redact/offload, append span + chain link (fsync each). Returns (disk_span, link).

    Synchronous, one span at a time. `SageRecorder` uses `LiveJournalWriter` instead, which
    writes the same records under a selectable durability mode.
    """
    root = Path(directory)
    prepared = disk_span or prepare_span_for_disk(
        span,
        blob_store=blob_store,
        redaction_policy=redaction_policy,
        blob_threshold=blob_threshold,
    )
    content = dict(content_by_id or {})
    if prepared.parent_id and prepared.parent_id not in content:
        parent_hash = lookup_content_hash_from_chain(root, prepared.parent_id)
        if parent_hash:
            content[prepared.parent_id] = parent_hash
    content[prepared.span_id] = span_content_hash(prepared)
    link = make_chain_link(prepared, index=index, prev_hash=prev_hash, content_by_id=content)
    append_span_line(directory, prepared)
    append_chain_link(directory, link)
    return prepared, link


def live_manifest_header(bundle: IncidentBundle, *, live: bool = True) -> dict[str, Any]:
    """Every live-manifest field that does not change when a span closes.

    The result shares no mutable container with the bundle, so a writer thread may serialize it
    while the recording thread keeps mutating the bundle.
    """
    from sage.audit import _scrub_string, resolve_redaction_rules

    fragments, patterns = resolve_redaction_rules(bundle.redaction_policy)
    title = _scrub_string(bundle.title, path="title", redacted_paths=None, value_patterns=patterns)
    hint = bundle.root_cause_hint
    if isinstance(hint, str):
        hint = _scrub_string(hint, path="root_cause_hint", redacted_paths=None, value_patterns=patterns)
    elif hint is not None:
        hint = copy.deepcopy(hint)
    return {
        "schema_version": bundle.schema_version,
        "bundle_id": bundle.bundle_id,
        "title": title or bundle.title,
        "created_at": bundle.created_at,
        "source": bundle.source.to_dict(),
        "status": "partial",
        "root_cause_hint": hint,
        "metadata": {
            **redact_value(bundle.metadata, key_fragments=fragments, value_patterns=patterns),
            "storage": "sage.journal.v1",
            "spans_file": SPANS_JSONL,
            "chain_file": CHAIN_JSONL,
            "live_recording": live,
            "manifest_wal": MANIFEST_WAL,
        },
        "redactions": copy.deepcopy(bundle.redactions),
        "redaction_policy": copy.deepcopy(bundle.redaction_policy),
        "audit": {"chain": [], "bundle_hash": ""},
        "chain_file": CHAIN_JSONL,
        "spans_file": SPANS_JSONL,
    }


@dataclass
class LiveManifestSnapshot:
    """What the live manifest should say once the spans queued so far are on disk."""

    header: dict[str, Any]
    spans: list[SageSpan]  # the bundle's span list; only the first `span_count` entries are read
    span_count: int
    chain_tip: str
    wal_ts: str

    def to_manifest(self) -> dict[str, Any]:
        return {
            **self.header,
            "span_count": self.span_count,
            "span_ids": [s.span_id for s in self.spans[: self.span_count]],
            "chain_tip": self.chain_tip,
        }


def snapshot_live_manifest(
    bundle: IncidentBundle,
    *,
    live: bool = True,
    chain_tip: str | None = None,
    header: dict[str, Any] | None = None,
) -> LiveManifestSnapshot:
    return LiveManifestSnapshot(
        header=header if header is not None else live_manifest_header(bundle, live=live),
        spans=bundle.spans,
        span_count=len(bundle.spans),
        chain_tip=chain_tip or ZERO_HASH,
        wal_ts=utc_now(),
    )


def _append_bytes(path: Path, data: bytes, *, fsync: bool) -> None:
    with open(path, "ab") as handle:
        handle.write(data)
        handle.flush()
        if fsync:
            os.fsync(handle.fileno())


def _fsync_existing(path: Path) -> None:
    if not path.exists():
        return
    with open(path, "ab") as handle:
        os.fsync(handle.fileno())


def _commit_live_records(
    root: Path,
    records: list[tuple[bytes, bytes]],
    snapshot: LiveManifestSnapshot | None,
    *,
    fsync: bool,
) -> None:
    """Append span lines, then chain links, then the manifest WAL record, then replace the manifest.

    The order is the crash contract: on disk, spans >= chain links >= manifest tip. Recovery
    truncates to the chain, so a crash between any two steps loses nothing that was complete.
    """
    if records:
        _append_bytes(root / SPANS_JSONL, b"".join(r[0] for r in records), fsync=fsync)
        _append_bytes(root / CHAIN_JSONL, b"".join(r[1] for r in records), fsync=fsync)
    if snapshot is not None:
        manifest = snapshot.to_manifest()
        # WAL first (append-only), then atomic tip replace — power-loss safe.
        wal_line = _jsonl_line({**manifest, "wal_ts": snapshot.wal_ts})
        _append_bytes(root / MANIFEST_WAL, wal_line.encode("utf-8") + _LINESEP, fsync=fsync)
        # Live manifests are intentionally unsealed.
        _atomic_write_text(
            root / MANIFEST_NAME, json.dumps(manifest, indent=2, sort_keys=True), fsync=fsync
        )


_OPEN_WRITERS: "weakref.WeakSet[LiveJournalWriter]" = weakref.WeakSet()


def _flush_writers_at_exit() -> None:
    """Commit what a recorder left queued when the interpreter exits without a seal."""
    failure: BaseException | None = None
    for writer in list(_OPEN_WRITERS):
        try:
            writer.close()
        except BaseException as exc:
            failure = exc
    if failure is not None:
        raise failure


atexit.register(_flush_writers_at_exit)


class LiveJournalWriter:
    """Writes live-journal records under one durability mode. Thread-safe.

    - `span`: `append` commits and fsyncs in the calling thread (four fsyncs per span). Nothing
      that `append` returned for can be lost.
    - `batch`: `append` queues the record; a background thread group-commits with fsync when the
      oldest queued span is `batch_interval_ms` old or `batch_max_spans` are queued. A crash loses
      at most the spans that were queued or in the commit under way.
    - `close`: like `batch` but without fsync until `flush()` / `close()`. A process crash loses
      what `batch` would; an operating-system crash or power loss can lose anything written since
      the last `flush()`.

    `append` blocks once `max_uncommitted` spans are waiting, so the loss window is bounded even
    when the disk is slower than the recorder. A failure in the background thread is raised from
    the next `append` / `flush` and from `close`; it is never dropped.
    """

    def __init__(
        self,
        directory: str | Path,
        *,
        durability: str | None = None,
        batch_interval_ms: float = DEFAULT_BATCH_INTERVAL_MS,
        batch_max_spans: int = DEFAULT_BATCH_MAX_SPANS,
        max_uncommitted: int | None = None,
        pre_commit: Callable[[], None] | None = None,
    ) -> None:
        self.root = Path(directory)
        self.durability = resolve_durability(durability)
        if batch_interval_ms < 0:
            raise ValueError("batch_interval_ms must be >= 0")
        if batch_max_spans < 1:
            raise ValueError("batch_max_spans must be >= 1")
        self.batch_interval_s = float(batch_interval_ms) / 1000.0
        self.batch_max_spans = int(batch_max_spans)
        self.max_uncommitted = int(
            max_uncommitted if max_uncommitted is not None else self.batch_max_spans * MAX_UNCOMMITTED_BATCHES
        )
        if self.max_uncommitted < 1:
            raise ValueError("max_uncommitted must be >= 1")
        # Runs before each commit (the recorder uses it to fsync blobs the queued spans refer to).
        self._pre_commit = pre_commit
        self._cond = threading.Condition()
        self._io_lock = threading.Lock()
        self._pending: list[tuple[bytes, bytes]] = []
        self._pending_manifest: LiveManifestSnapshot | None = None
        self._oldest_pending_at = 0.0
        self._in_flight = 0
        self._urgent = False
        self._closed = False
        self._error: BaseException | None = None
        self._error_raised_at_close = False
        self._unsynced = False  # close mode: data written since the last fsync
        self._thread: threading.Thread | None = None
        self.commits = 0
        self.root.mkdir(parents=True, exist_ok=True)
        _OPEN_WRITERS.add(self)

    # -- public API ---------------------------------------------------------------------------

    @property
    def closed(self) -> bool:
        return self._closed

    def write_manifest(self, snapshot: LiveManifestSnapshot) -> None:
        """Write the manifest now, durably, in the calling thread (used when recording starts)."""
        self.flush(sync=False)
        with self._io_lock:
            _commit_live_records(self.root, [], snapshot, fsync=True)
            self.commits += 1

    def append(self, span_line: str, chain_line: str, snapshot: LiveManifestSnapshot | None) -> None:
        record = (span_line.encode("utf-8") + _LINESEP, chain_line.encode("utf-8") + _LINESEP)
        if self.durability == DURABILITY_SPAN:
            with self._cond:
                self._raise_if_unusable()
            with self._io_lock:
                if self._pre_commit is not None:
                    self._pre_commit()
                _commit_live_records(self.root, [record], snapshot, fsync=True)
                self.commits += 1
            return
        with self._cond:
            self._raise_if_unusable()
            while len(self._pending) + self._in_flight >= self.max_uncommitted:
                self._urgent = True
                self._ensure_thread()
                self._cond.notify_all()
                self._cond.wait()
                self._raise_if_unusable()
            if not self._pending:
                self._oldest_pending_at = time.monotonic()
            self._pending.append(record)
            if snapshot is not None:
                self._pending_manifest = snapshot
            self._ensure_thread()
            if len(self._pending) == 1 or len(self._pending) >= self.batch_max_spans:
                self._cond.notify_all()

    def flush(self, *, sync: bool = True) -> None:
        """Block until every appended record is committed. With `sync`, also fsync (`close` mode)."""
        with self._cond:
            self._raise_if_failed()
            while self._pending or self._in_flight:
                self._urgent = True
                self._ensure_thread()
                self._cond.notify_all()
                self._cond.wait()
                self._raise_if_failed()
        if sync:
            self._sync_unsynced()

    def close(self) -> None:
        """Flush, fsync, and stop the writer thread. Raises a pending writer failure once."""
        try:
            if not self._closed:
                self.flush(sync=True)
        except JournalWriteError:
            if self._error_raised_at_close:
                return
            self._error_raised_at_close = True
            raise
        finally:
            with self._cond:
                self._closed = True
                thread = self._thread
                self._cond.notify_all()
            if thread is not None and thread is not threading.current_thread():
                thread.join()
            _OPEN_WRITERS.discard(self)

    # -- internals ----------------------------------------------------------------------------

    def _raise_if_failed(self) -> None:
        if self._error is not None:
            raise JournalWriteError(
                f"live journal writer failed under {self.root}: {self._error!r}; "
                "spans recorded after the failure are not on disk"
            ) from self._error

    def _raise_if_unusable(self) -> None:
        self._raise_if_failed()
        if self._closed:
            raise JournalWriteError(f"live journal writer for {self.root} is closed")

    def _ensure_thread(self) -> None:
        # Caller holds self._cond.
        if self._thread is None and self._error is None:
            self._thread = threading.Thread(
                target=self._run, name="sage-journal-writer", daemon=True
            )
            self._thread.start()

    def _sync_unsynced(self) -> None:
        with self._io_lock:
            if not self._unsynced:
                return
            try:
                if self._pre_commit is not None:
                    self._pre_commit()
                for name in (SPANS_JSONL, CHAIN_JSONL, MANIFEST_WAL, MANIFEST_NAME):
                    _fsync_existing(self.root / name)
                self._unsynced = False
            except BaseException as exc:
                with self._cond:
                    if self._error is None:
                        self._error = exc
                self._raise_if_failed()

    def _run(self) -> None:
        fsync = self.durability == DURABILITY_BATCH
        while True:
            with self._cond:
                while True:
                    if self._pending:
                        age = time.monotonic() - self._oldest_pending_at
                        if (
                            self._urgent
                            or self._closed
                            or len(self._pending) >= self.batch_max_spans
                            or age >= self.batch_interval_s
                        ):
                            break
                        self._cond.wait(timeout=self.batch_interval_s - age)
                        continue
                    self._urgent = False
                    if self._closed or not self._cond.wait(timeout=_WRITER_IDLE_EXIT_S):
                        if not self._pending:
                            self._thread = None
                            self._cond.notify_all()
                            return
                records = self._pending
                snapshot = self._pending_manifest
                self._pending = []
                self._pending_manifest = None
                self._in_flight = len(records)
            try:
                with self._io_lock:
                    if self._pre_commit is not None:
                        self._pre_commit()
                    _commit_live_records(self.root, records, snapshot, fsync=fsync)
                    self.commits += 1
                    if not fsync:
                        self._unsynced = True
            except BaseException as exc:  # surfaced by the next append / flush / close
                with self._cond:
                    self._error = exc
                    self._in_flight = 0
                    self._pending = []
                    self._thread = None
                    self._cond.notify_all()
                return
            with self._cond:
                self._in_flight = 0
                self._cond.notify_all()


def write_live_manifest(
    bundle: IncidentBundle,
    directory: str | Path,
    *,
    live: bool = True,
    chain_tip: str | None = None,
) -> Path:
    """Write the live manifest now (WAL record + atomic replace, both fsynced)."""
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    snapshot = snapshot_live_manifest(bundle, live=live, chain_tip=chain_tip)
    _commit_live_records(root, [], snapshot, fsync=True)
    return root / MANIFEST_NAME


def recover_manifest_from_wal(directory: str | Path) -> dict[str, Any] | None:
    """Restore manifest.sage.json from the last complete WAL record."""
    root = Path(directory)
    objects, rejected = load_jsonl_objects(root / MANIFEST_WAL)
    if not objects:
        return None
    last = dict(objects[-1])
    last.pop("wal_ts", None)
    _atomic_write_text(root / MANIFEST_NAME, json.dumps(last, indent=2, sort_keys=True))
    if rejected:
        last["_wal_rejected_tail_bytes"] = rejected
    return last


def verify_live_chain_prefix(
    spans: list[dict[str, Any]],
    chain: list[dict[str, Any]],
) -> str:
    """Recompute content/link hashes for a live journal prefix (fail-closed)."""
    if len(spans) != len(chain):
        raise ChainIntegrityError(
            f"span/chain length mismatch: spans={len(spans)} chain={len(chain)}"
        )
    content_by_id: dict[str, str] = {}
    prev = ZERO_HASH
    for index, (raw, link) in enumerate(zip(spans, chain)):
        span = SageSpan.from_dict(raw)
        require_normal_form(raw, span.to_dict(), f"live span at index={index}")
        content = span_content_hash(span)
        content_by_id[span.span_id] = content
        expected = make_chain_link(
            span,
            index=index,
            prev_hash=prev,
            content_by_id=content_by_id,
        )
        if str(link.get("content_hash") or link.get("span_hash") or "") != content:
            raise ChainIntegrityError(
                f"live content_hash mismatch at index={index} span_id={span.span_id}"
            )
        if str(link.get("prev_hash") or "") != prev:
            raise ChainIntegrityError(f"live prev_hash mismatch at index={index}")
        if str(link.get("hash") or "") != expected["hash"]:
            raise ChainIntegrityError(
                f"live chain link hash mismatch at index={index} span_id={span.span_id}"
            )
        parent_id = span.parent_id
        if parent_id:
            expected_parent = content_by_id.get(parent_id)
            claimed_parent = link.get("parent_content_hash")
            if expected_parent and claimed_parent and claimed_parent != expected_parent:
                raise ChainIntegrityError(
                    f"live parent_content_hash mismatch at index={index} parent_id={parent_id}"
                )
        prev = str(link["hash"])
    return prev if chain else ZERO_HASH


MALFORMED_INPUT_ERRORS: tuple[type[BaseException], ...] = (
    ValueError,  # includes json.JSONDecodeError and UnicodeDecodeError
    KeyError,
    TypeError,
    AttributeError,
    IndexError,
)


def verify_journal(
    directory: str | Path,
    *,
    allow_live: bool = True,
) -> dict[str, Any]:
    """Fail-closed journal verification for CI / `sage verify-journal`.

    Every rejection is a `SageError`: malformed content raises `ChainIntegrityError`.
    """
    try:
        return _verify_journal(directory, allow_live=allow_live)
    except SageError:
        raise
    except MALFORMED_INPUT_ERRORS as exc:
        raise ChainIntegrityError(f"malformed journal: {type(exc).__name__}: {exc}") from exc


def _first_corrupt_line(path: Path) -> int | None:
    """1-based number of the first complete line that is not a JSON object.

    A crash can only tear the unterminated last line; a bad line that ends in a newline is
    corruption. NUL-only lines (what power loss can leave behind) count as torn, not corrupt.
    """
    if not path.exists():
        return None
    for number, line in enumerate(path.read_bytes().split(b"\n")[:-1], start=1):
        text = line.strip()
        if not text.strip(b"\x00"):
            continue
        try:
            obj = json.loads(text.decode("utf-8"))
        except ValueError:
            return number
        if not isinstance(obj, dict):
            return number
    return None


def _verify_journal(directory: str | Path, *, allow_live: bool) -> dict[str, Any]:
    root = journal_root(directory)
    for name in (SPANS_JSONL, CHAIN_JSONL):
        corrupt = _first_corrupt_line(root / name)
        if corrupt is not None:
            raise ChainIntegrityError(f"{name} line {corrupt} is corrupt (not a torn tail)")
    if not (root / MANIFEST_NAME).exists():
        recovered = recover_manifest_from_wal(root)
        if recovered is None:
            raise ChainIntegrityError(f"missing manifest and empty WAL under {root}")
    manifest = json.loads(read_text_file(root / MANIFEST_NAME))
    live = bool((manifest.get("metadata") or {}).get("live_recording"))
    spans, rejected = load_spans_jsonl(root / SPANS_JSONL)
    chain, chain_rej = load_jsonl_objects(root / CHAIN_JSONL)
    rejected += chain_rej
    if rejected:
        raise FaultRecoveryError(
            f"journal has torn/corrupt tail ({rejected} bytes); refuse verify — use recover_journal"
        )
    tip = chain[-1]["hash"] if chain else ZERO_HASH
    claimed_tip = manifest.get("chain_tip") or ZERO_HASH
    if claimed_tip != tip:
        raise ChainIntegrityError(
            f"chain_tip mismatch: manifest={claimed_tip!r} actual={tip!r}"
        )
    if len(spans) != len(chain):
        raise ChainIntegrityError(
            f"span/chain length mismatch: spans={len(spans)} chain={len(chain)}"
        )
    if live:
        if not allow_live:
            raise ChainIntegrityError("live journal refused (allow_live=False)")
        # Live chain links are written by make_chain_link — recompute them.
        actual_tip = verify_live_chain_prefix(spans, chain)
        if actual_tip != tip:
            raise ChainIntegrityError(
                f"recomputed tip mismatch: chain={tip!r} recomputed={actual_tip!r}"
            )
        return {
            "ok": True,
            "live": True,
            "path": str(root),
            "bundle_id": manifest.get("bundle_id"),
            "span_count": len(spans),
            "chain_tip": tip,
            "content_verified": True,
            "wal_records": len(load_jsonl_objects(root / MANIFEST_WAL)[0])
            if (root / MANIFEST_WAL).exists()
            else 0,
        }

    # Sealed journals: full require_verified path (audit chain builder ≠ live links).
    bundle = load_journal(root, verify=True)
    from sage.merkle import chain_merkle_root

    return {
        "ok": True,
        "live": False,
        "path": str(root),
        "bundle_id": bundle.bundle_id,
        "bundle_hash": bundle.audit.bundle_hash,
        "span_count": len(bundle.spans),
        "chain_tip": tip,
        "merkle_root": manifest.get("merkle_root") or chain_merkle_root(bundle.audit.chain),
        "manifest_seal": manifest.get("manifest_seal"),
        "content_verified": True,
    }


def load_jsonl_objects(path: Path) -> tuple[list[dict[str, Any]], int]:
    if not path.exists():
        return [], 0
    raw = path.read_bytes()
    if not raw:
        return [], 0
    text = raw.decode("utf-8", errors="replace")
    lines = text.split("\n")
    objects: list[dict[str, Any]] = []
    rejected = 0
    complete_lines = lines if text.endswith("\n") else lines[:-1]
    if not text.endswith("\n") and lines:
        rejected = len(lines[-1].encode("utf-8"))
    for line in complete_lines:
        if not line.strip():
            continue
        try:
            objects.append(json.loads(line))
        except json.JSONDecodeError:
            rejected += len(line.encode("utf-8"))
            break
    return objects, rejected


def load_spans_jsonl(path: str | Path) -> tuple[list[dict[str, Any]], int]:
    return load_jsonl_objects(Path(path))


def load_journal(
    directory: str | Path,
    *,
    verify: bool = False,
) -> IncidentBundle:
    root = journal_root(directory)
    manifest = json.loads(read_text_file(root / MANIFEST_NAME))
    span_dicts, rejected = load_spans_jsonl(root / SPANS_JSONL)
    chain_dicts, chain_rejected = load_jsonl_objects(root / CHAIN_JSONL)
    rejected += chain_rejected
    if rejected and verify:
        raise FaultRecoveryError(
            f"journal has torn/corrupt tail ({rejected} bytes); refuse verify — use recover_journal"
        )

    chain = chain_dicts or list((manifest.get("audit") or {}).get("chain") or [])
    bundle = IncidentBundle(
        title=str(manifest.get("title") or "journal"),
        bundle_id=str(manifest.get("bundle_id") or "bundle_unknown"),
        schema_version=str(manifest.get("schema_version") or SCHEMA_VERSION),
        created_at=str(manifest.get("created_at") or utc_now()),
        source=BundleSource(**(manifest.get("source") or {})),
        status=manifest.get("status") or "partial",  # type: ignore[arg-type]
        root_cause_hint=manifest.get("root_cause_hint"),
        metadata=dict(manifest.get("metadata") or {}),
        redactions=list(manifest.get("redactions") or []),
        redaction_policy=dict(manifest.get("redaction_policy") or {}),
        audit=AuditBlock(
            chain=chain,
            bundle_hash=str((manifest.get("audit") or {}).get("bundle_hash") or ""),
        ),
    )
    for index, raw in enumerate(span_dicts):
        span = SageSpan.from_dict(raw, default_trace_id=bundle.bundle_id)
        if not span.trace_id:
            span.trace_id = bundle.bundle_id
        if verify:
            require_normal_form(raw, span.to_dict(), f"span at index={index}")
        bundle.spans.append(span)
    if verify:
        if manifest.get("manifest_seal"):
            verify_manifest_seal(manifest)
            tip = manifest.get("chain_tip")
            if bundle.audit.chain:
                actual_tip = bundle.audit.chain[-1]["hash"]
                if tip and tip != actual_tip:
                    raise ChainIntegrityError(
                        f"chain_tip mismatch: manifest={tip!r} actual={actual_tip!r}"
                    )
            claimed_merkle = manifest.get("merkle_root")
            if claimed_merkle:
                from sage.merkle import chain_merkle_root

                actual_merkle = chain_merkle_root(bundle.audit.chain)
                if claimed_merkle != actual_merkle:
                    raise ChainIntegrityError(
                        f"merkle_root mismatch: claimed={claimed_merkle!r} actual={actual_merkle!r}"
                    )
        require_verified(bundle)
    return bundle


def recover_journal(directory: str | Path) -> RecoveryReport:
    root = journal_root(directory)
    try:
        manifest = json.loads(read_text_file(root / MANIFEST_NAME))
    except Exception as exc:
        restored = recover_manifest_from_wal(root)
        if restored is None:
            return RecoveryReport(
                ok=False,
                path=str(root),
                boundary=None,
                errors=[f"manifest unreadable: {exc}; WAL empty"],
            )
        manifest = restored
    span_dicts, rejected = load_spans_jsonl(root / SPANS_JSONL)
    chain_dicts, chain_rej = load_jsonl_objects(root / CHAIN_JSONL)
    rejected += chain_rej
    bundle = IncidentBundle(
        title=str(manifest.get("title") or "journal-recovered"),
        bundle_id=str(manifest.get("bundle_id") or "bundle_recovered"),
        source=BundleSource(**(manifest.get("source") or {"run_id": "recovered"})),
        status="partial",
        metadata={
            **dict(manifest.get("metadata") or {}),
            "fault_recovery": True,
            "crash_boundary": True,
            "storage": "sage.journal.v1",
            "rejected_tail_bytes": rejected,
        },
    )
    for raw in span_dicts:
        try:
            span = SageSpan.from_dict(raw, default_trace_id=bundle.bundle_id)
            if not span.end_time:
                span.end_time = span.start_time or utc_now()
            bundle.spans.append(span)
        except Exception:
            break
    if not bundle.spans:
        return RecoveryReport(
            ok=False,
            path=str(root),
            boundary=CrashBoundary(
                last_valid_chain_index=-1,
                last_valid_hash=ZERO_HASH,
                recovered_span_count=0,
                truncated=True,
                failure_anchor={
                    "kind": "crash_boundary",
                    "message": "no complete JSONL span lines",
                },
                rejected_tail_bytes=rejected,
            ),
            errors=["empty recoverable prefix"],
        )

    # Prefer recovered chain.jsonl only if it recomputes; else rebuild.
    chain_rebuilt = False
    if chain_dicts and len(chain_dicts) <= len(bundle.spans):
        candidate_spans = [s.to_dict() for s in bundle.spans[: len(chain_dicts)]]
        try:
            verify_live_chain_prefix(candidate_spans, chain_dicts)
            bundle.spans = bundle.spans[: len(chain_dicts)]
            chain = chain_dicts
        except ChainIntegrityError:
            chain = enrich_audit_chain(bundle)
            chain_rebuilt = True
            bundle.metadata["rejected_chain_prefix"] = True
    else:
        chain = enrich_audit_chain(bundle)
        chain_rebuilt = True
    bundle.audit = AuditBlock(chain=chain, bundle_hash="")
    last = chain[-1]["hash"] if chain else ZERO_HASH
    bundle.metadata["chain_rebuilt"] = chain_rebuilt
    bundle.metadata["failure_anchor"] = {
        "kind": "crash_boundary",
        "message": "torn JSONL tail dropped",
        "last_valid_hash": last,
        "last_valid_chain_index": len(chain) - 1,
        "rejected_tail_bytes": rejected,
        "chain_rebuilt": chain_rebuilt,
    }
    return RecoveryReport(
        ok=False,
        path=str(root),
        boundary=CrashBoundary(
            last_valid_chain_index=len(chain) - 1,
            last_valid_hash=last,
            recovered_span_count=len(bundle.spans),
            truncated=bool(rejected),
            failure_anchor=bundle.metadata["failure_anchor"],
            rejected_tail_bytes=rejected,
        ),
        bundle=bundle,
        errors=["journal recovered prefix only; refuse full verification"] if rejected else [],
    )
