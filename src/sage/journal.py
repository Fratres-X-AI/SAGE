from __future__ import annotations

import copy
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sage.audit import (
    build_audit_chain,
    compute_bundle_hash,
    order_spans,
    redact_value,
    require_verified,
    sha256_digest,
)
from sage.blobs import BlobStore, DEFAULT_THRESHOLD, apply_offload_to_incident
from sage.errors import ChainIntegrityError, FaultRecoveryError
from sage.fault import CrashBoundary, RecoveryReport
from sage.schema import AuditBlock, BundleSource, IncidentBundle, SCHEMA_VERSION, SageSpan, utc_now

SPANS_JSONL = "spans.jsonl"
CHAIN_JSONL = "chain.jsonl"
MANIFEST_NAME = "manifest.sage.json"
MANIFEST_WAL = "manifest.wal.jsonl"
ZERO_HASH = "0" * 64


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
) -> SageSpan:
    """Redact secrets and CAS-offload large payloads before any journal append."""
    from sage.audit import DEFAULT_REDACTION_KEYS, DEFAULT_VALUE_PATTERNS
    from sage.schema import IncidentBundle

    clone = SageSpan.from_dict(copy.deepcopy(span.to_dict()))
    policy = redaction_policy or {}
    fragments = tuple(policy.get("key_fragments") or DEFAULT_REDACTION_KEYS)
    patterns = tuple(policy.get("value_patterns") or DEFAULT_VALUE_PATTERNS)
    clone.inputs = redact_value(clone.inputs, key_fragments=fragments, value_patterns=patterns)
    clone.outputs = redact_value(clone.outputs, key_fragments=fragments, value_patterns=patterns)
    clone.attributes = redact_value(clone.attributes, key_fragments=fragments, value_patterns=patterns)
    clone.data = redact_value(clone.data, key_fragments=fragments, value_patterns=patterns)
    clone.events = [
        redact_value(ev, key_fragments=fragments, value_patterns=patterns) if isinstance(ev, dict) else ev
        for ev in (clone.events or [])
    ]

    if blob_store is not None:
        shell = IncidentBundle(title="tmp", spans=[clone], metadata={})
        apply_offload_to_incident(shell, blob_store, threshold=blob_threshold)
        clone = shell.spans[0]
    return clone


def apply_sanitized_fields(target: SageSpan, prepared: SageSpan) -> None:
    """Copy redact/CAS fields onto the in-memory span (secrets leave the process heap)."""
    target.inputs = prepared.inputs
    target.outputs = prepared.outputs
    target.attributes = prepared.attributes
    target.data = prepared.data


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


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".sage-w-", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, str(path))
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
        os.replace(tmp, str(paths.spans))
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
        os.replace(c_tmp, str(paths.chain))
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
    """Redact/offload, append span + chain link. Returns (disk_span, link)."""
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


def write_live_manifest(
    bundle: IncidentBundle,
    directory: str | Path,
    *,
    live: bool = True,
    chain_tip: str | None = None,
) -> Path:
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    path = root / MANIFEST_NAME
    tip = chain_tip or ZERO_HASH
    manifest = {
        "schema_version": bundle.schema_version,
        "bundle_id": bundle.bundle_id,
        "title": bundle.title,
        "created_at": bundle.created_at,
        "source": bundle.source.to_dict(),
        "status": "partial",
        "root_cause_hint": bundle.root_cause_hint,
        "metadata": {
            **bundle.metadata,
            "storage": "sage.journal.v1",
            "spans_file": SPANS_JSONL,
            "chain_file": CHAIN_JSONL,
            "live_recording": live,
            "manifest_wal": MANIFEST_WAL,
        },
        "redactions": bundle.redactions,
        "redaction_policy": bundle.redaction_policy,
        "audit": {"chain": [], "bundle_hash": ""},
        "span_count": len(bundle.spans),
        "span_ids": [s.span_id for s in bundle.spans],
        "chain_tip": tip,
        "chain_file": CHAIN_JSONL,
        "spans_file": SPANS_JSONL,
    }
    # WAL first (append-only), then atomic tip replace — power-loss safe.
    wal_record = {**manifest, "wal_ts": utc_now()}
    append_jsonl_line(root / MANIFEST_WAL, wal_record)
    # Live manifests are intentionally unsealed.
    _atomic_write_text(path, json.dumps(manifest, indent=2, sort_keys=True))
    return path


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


def verify_journal(
    directory: str | Path,
    *,
    allow_live: bool = True,
) -> dict[str, Any]:
    """Fail-closed journal verification for CI / `sage verify-journal`."""
    root = journal_root(directory)
    if not (root / MANIFEST_NAME).exists():
        recovered = recover_manifest_from_wal(root)
        if recovered is None:
            raise ChainIntegrityError(f"missing manifest and empty WAL under {root}")
    manifest = json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))
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
    manifest = json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))
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
    for raw in span_dicts:
        span = SageSpan.from_dict(raw, default_trace_id=bundle.bundle_id)
        if not span.trace_id:
            span.trace_id = bundle.bundle_id
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
        manifest = json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))
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
