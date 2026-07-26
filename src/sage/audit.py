from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from sage.schema import AuditBlock, IncidentBundle, SCHEMA_VERSION

DEFAULT_REDACTION_KEYS = (
    "api_key",
    "authorization",
    "cookie",
    "credential",
    "password",
    "secret",
    "token",
)

DEFAULT_VALUE_PATTERNS = (
    r"sk-[A-Za-z0-9_\-]{8,}",
    r"Bearer\s+[A-Za-z0-9_\-\.]+",
)

# Usage / metric keys that contain "token" but are not secrets.
SAFE_KEY_ALLOWLIST = frozenset(
    {
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "prompt_tokens",
        "completion_tokens",
        "tokens",
        "token_count",
    }
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _scrub_string(
    text: str,
    *,
    path: str,
    redacted_paths: list[dict[str, str]] | None,
    value_patterns: tuple[str, ...],
) -> str:
    scrubbed = text
    for pattern in value_patterns:
        regex = re.compile(pattern)
        if regex.search(scrubbed):
            scrubbed, count = regex.subn("[REDACTED]", scrubbed)
            if count and redacted_paths is not None:
                redacted_paths.append({"path": path, "reason": f"value_pattern:{pattern}"})
    return scrubbed


def redact_value(
    value: Any,
    *,
    path: str = "",
    redacted_paths: list[dict[str, str]] | None = None,
    key_fragments: tuple[str, ...] = DEFAULT_REDACTION_KEYS,
    value_patterns: tuple[str, ...] = DEFAULT_VALUE_PATTERNS,
) -> Any:
    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            key_l = str(key).lower()
            is_sensitive = any(fragment in key_l for fragment in key_fragments) and (
                key_l not in SAFE_KEY_ALLOWLIST and not key_l.endswith("_tokens")
            )
            if is_sensitive:
                redacted[key] = "[REDACTED]"
                if redacted_paths is not None:
                    redacted_paths.append({"path": child_path, "reason": "sensitive_key"})
            else:
                redacted[key] = redact_value(
                    child,
                    path=child_path,
                    redacted_paths=redacted_paths,
                    key_fragments=key_fragments,
                    value_patterns=value_patterns,
                )
        return redacted
    if isinstance(value, list):
        return [
            redact_value(
                child,
                path=f"{path}.{index}" if path else str(index),
                redacted_paths=redacted_paths,
                key_fragments=key_fragments,
                value_patterns=value_patterns,
            )
            for index, child in enumerate(value)
        ]
    if isinstance(value, str):
        return _scrub_string(
            value,
            path=path or "$",
            redacted_paths=redacted_paths,
            value_patterns=value_patterns,
        )
    return value


def redact_bundle(
    bundle: IncidentBundle,
    *,
    key_fragments: tuple[str, ...] | None = None,
    value_patterns: tuple[str, ...] | None = None,
) -> IncidentBundle:
    fragments = key_fragments or tuple(
        bundle.redaction_policy.get("key_fragments") or DEFAULT_REDACTION_KEYS
    )
    patterns = value_patterns or tuple(
        bundle.redaction_policy.get("value_patterns") or DEFAULT_VALUE_PATTERNS
    )
    # Bypass strict validation during clone of in-progress/raw bundles.
    raw = copy.deepcopy(bundle.to_dict())
    raw["audit"] = {"chain": [], "bundle_hash": ""}
    clone = IncidentBundle.from_dict(raw)
    redactions: list[dict[str, str]] = []
    clone.metadata = redact_value(
        clone.metadata,
        path="metadata",
        redacted_paths=redactions,
        key_fragments=fragments,
        value_patterns=patterns,
    )
    for span_index, span in enumerate(clone.spans):
        base = f"spans.{span_index}"
        span.inputs = redact_value(
            span.inputs,
            path=f"{base}.inputs",
            redacted_paths=redactions,
            key_fragments=fragments,
            value_patterns=patterns,
        )
        span.outputs = redact_value(
            span.outputs,
            path=f"{base}.outputs",
            redacted_paths=redactions,
            key_fragments=fragments,
            value_patterns=patterns,
        )
        span.attributes = redact_value(
            span.attributes,
            path=f"{base}.attributes",
            redacted_paths=redactions,
            key_fragments=fragments,
            value_patterns=patterns,
        )
        span.data = redact_value(
            span.data,
            path=f"{base}.data",
            redacted_paths=redactions,
            key_fragments=fragments,
            value_patterns=patterns,
        )
        span.events = [
            redact_value(
                ev,
                path=f"{base}.events.{ei}",
                redacted_paths=redactions,
                key_fragments=fragments,
                value_patterns=patterns,
            )
            if isinstance(ev, dict)
            else ev
            for ei, ev in enumerate(span.events or [])
        ]
    clone.redactions = [*clone.redactions, *redactions]
    clone.redaction_policy = {
        **clone.redaction_policy,
        "key_fragments": list(fragments),
        "value_patterns": list(patterns),
        "applied": True,
    }
    return clone


def order_spans(bundle: IncidentBundle) -> IncidentBundle:
    bundle.sort_spans()
    return bundle


def build_audit_chain(bundle: IncidentBundle) -> list[dict[str, Any]]:
    """Hash-chain with content_hash + parent_content_hash for forge detection."""
    content = {span.span_id: sha256_digest(span.to_dict()) for span in bundle.spans}
    chain: list[dict[str, Any]] = []
    previous_hash = "0" * 64
    for index, span in enumerate(bundle.spans):
        parent_hash = content.get(span.parent_id) if span.parent_id else None
        record = {
            "index": index,
            "span_id": span.span_id,
            "span_type": span.type,
            "span_name": span.name,
            "timestamp": span.end_time or span.start_time or "",
            "prev_hash": previous_hash,
            "span_hash": content[span.span_id],
            "content_hash": content[span.span_id],
            "parent_id": span.parent_id,
            "parent_content_hash": parent_hash,
        }
        record["hash"] = sha256_digest(record)
        chain.append(record)
        previous_hash = record["hash"]
    return chain


def compute_bundle_hash(bundle: IncidentBundle) -> str:
    """Hash redacted bundle content excluding mutable audit hashes themselves."""
    payload = bundle.to_dict()
    payload["audit"] = {"chain": payload.get("audit", {}).get("chain", []), "bundle_hash": ""}
    # Drop compatibility mirrors that duplicate audit
    payload.pop("audit_chain", None)
    return sha256_digest(payload)


def attach_audit_chain(bundle: IncidentBundle) -> IncidentBundle:
    order_spans(bundle)
    chain = build_audit_chain(bundle)
    bundle.audit = AuditBlock(chain=chain, bundle_hash="")
    bundle.audit.bundle_hash = compute_bundle_hash(bundle)
    return bundle


def verify_audit_chain(bundle: IncidentBundle) -> bool:
    expected_chain = build_audit_chain(bundle)
    if expected_chain != bundle.audit.chain:
        return False
    expected_hash = compute_bundle_hash(bundle)
    return expected_hash == bundle.audit.bundle_hash


def finalize_bundle(
    bundle: IncidentBundle,
    *,
    redact: bool = True,
    status: str | None = None,
    blob_store: Any | None = None,
    blob_threshold: int | None = None,
    offload_blobs: bool = True,
) -> IncidentBundle:
    """Canonical finalize: redact → CAS offload → validate → hash chain → bundle_hash."""
    from sage.blobs import DEFAULT_THRESHOLD, BlobStore, apply_offload_to_incident
    from sage.schema import ensure_typed_data

    for span in bundle.spans:
        if not span.trace_id:
            span.trace_id = bundle.bundle_id
        ensure_typed_data(span)
    working = redact_bundle(bundle) if redact else bundle
    if status is not None:
        working.status = status  # type: ignore[assignment]
    working.schema_version = SCHEMA_VERSION
    for span in working.spans:
        ensure_typed_data(span)

    if offload_blobs:
        store = blob_store if isinstance(blob_store, BlobStore) else BlobStore(blob_store)
        threshold = DEFAULT_THRESHOLD if blob_threshold is None else int(blob_threshold)
        apply_offload_to_incident(working, store, threshold=threshold)

    working.validate(strict=True)
    return attach_audit_chain(working)


def verify_parent_integrity(bundle: IncidentBundle) -> None:
    """Fail closed if parent_id references are broken (tamper / corruption signal)."""
    ids = {span.span_id for span in bundle.spans}
    for span in bundle.spans:
        if span.parent_id is None:
            continue
        if span.parent_id not in ids:
            raise ValueError(
                f"broken parent_id reference: span {span.span_id} parent_id={span.parent_id!r} not in bundle"
            )


def verify_parent_content_hashes(bundle: IncidentBundle) -> None:
    """Fail closed if audit parent_content_hash does not match the parent's live content hash.

    Catches forged parent links that keep a valid parent_id but point at stale/wrong content.
    """
    from sage.errors import ChainIntegrityError

    content = {span.span_id: sha256_digest(span.to_dict()) for span in bundle.spans}
    by_span = {rec.get("span_id"): rec for rec in (bundle.audit.chain or [])}
    for span in bundle.spans:
        if not span.parent_id:
            continue
        rec = by_span.get(span.span_id)
        if not rec:
            continue
        claimed = rec.get("parent_content_hash")
        actual = content.get(span.parent_id)
        if claimed is None and actual is None:
            continue
        if claimed != actual:
            raise ChainIntegrityError(
                f"parent_content_hash mismatch for span {span.span_id}: "
                f"claimed={claimed!r} actual={actual!r} parent_id={span.parent_id}"
            )
        # Also ensure the parent_id recorded in the chain matches the span.
        if rec.get("parent_id") != span.parent_id:
            raise ChainIntegrityError(
                f"audit parent_id disagrees with span parent_id for {span.span_id}"
            )


def require_verified(bundle: IncidentBundle) -> IncidentBundle:
    from sage.concurrency import validate_monotonic_chain

    bundle.validate(strict=True)
    verify_parent_integrity(bundle)
    validate_monotonic_chain(bundle)
    if not verify_audit_chain(bundle):
        raise ValueError("audit chain or bundle_hash verification failed")
    verify_parent_content_hashes(bundle)
    return bundle
