from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from sage.audit import require_verified
from sage.blobs import BlobStore, rehydrate_bundle_dict
from sage.errors import BlobIntegrityError
from sage.journal import is_journal_path, journal_root, load_journal, save_journal
from sage.schema import IncidentBundle


def _resolve_store(
    data: dict,
    blob_store: str | Path | BlobStore | None,
) -> BlobStore:
    if isinstance(blob_store, BlobStore):
        return blob_store
    if blob_store is not None:
        return BlobStore(blob_store)
    meta = data.get("metadata") or {}
    root = meta.get("blob_store")
    return BlobStore(root) if root else BlobStore()


def rehydrate_bundle(
    bundle: IncidentBundle,
    *,
    blob_store: str | Path | BlobStore | None = None,
) -> IncidentBundle:
    raw = bundle.to_dict()
    store = _resolve_store(raw, blob_store)
    hydrated = rehydrate_bundle_dict(raw, store)
    out = IncidentBundle.from_dict(hydrated)
    out.audit = bundle.audit
    return out


def load_bundle(
    path: str | Path,
    *,
    verify: bool = False,
    rehydrate: bool = False,
    blob_store: str | Path | BlobStore | None = None,
) -> IncidentBundle:
    """Load a classic .sage.json bundle or a journal directory (spans.jsonl + manifest)."""
    p = Path(path)
    if is_journal_path(p):
        bundle = load_journal(journal_root(p), verify=verify)
        if not rehydrate:
            return bundle
        raw = bundle.to_dict()
        store = _resolve_store(raw, blob_store)
        try:
            hydrated = rehydrate_bundle_dict(raw, store)
        except BlobIntegrityError:
            raise
        out = IncidentBundle.from_dict(hydrated)
        out.audit = bundle.audit
        return out

    raw = json.loads(p.read_text(encoding="utf-8"))
    compact = IncidentBundle.from_dict(raw)
    if verify:
        require_verified(compact)
    if not rehydrate:
        return compact
    store = _resolve_store(raw, blob_store)
    try:
        hydrated = rehydrate_bundle_dict(raw, store)
    except BlobIntegrityError:
        raise
    bundle = IncidentBundle.from_dict(hydrated)
    bundle.audit = compact.audit
    return bundle


def load_bundle_compact(path: str | Path, *, verify: bool = False) -> IncidentBundle:
    return load_bundle(path, verify=verify, rehydrate=False)


def save_bundle(
    bundle: IncidentBundle,
    path: str | Path,
    *,
    blob_store: str | Path | BlobStore | None = None,
    offload: bool = False,
    blob_threshold: int | None = None,
    atomic: bool = True,
    format: str = "json",
) -> Path:
    """Persist bundle as classic JSON or journal directory (format='journal')."""
    from sage.audit import finalize_bundle

    output = Path(path)
    working = bundle
    if offload:
        working = finalize_bundle(
            bundle,
            redact=False,
            status=bundle.status,
            blob_store=blob_store,
            blob_threshold=blob_threshold,
            offload_blobs=True,
        )

    if format == "journal":
        save_journal(working, output)
        return output

    output.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(working.to_dict(), indent=2, sort_keys=True)
    if not atomic:
        output.write_text(payload, encoding="utf-8")
        return output
    fd, tmp_name = tempfile.mkstemp(prefix=".sage-bundle-", suffix=".tmp", dir=str(output.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, str(output))
    except Exception:
        Path(tmp_name).unlink(missing_ok=True)
        raise
    return output
