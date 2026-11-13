from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Mapping
from functools import lru_cache
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


@lru_cache(maxsize=512)
def _compiled_pattern(pattern: str) -> "re.Pattern[str]":
    """Compile a redaction value pattern once per process (invalid patterns still raise each time)."""
    return re.compile(pattern)


@lru_cache(maxsize=8192)
def _is_sensitive_key(key_l: str, key_fragments: tuple[str, ...]) -> bool:
    for fragment in key_fragments:
        if fragment in key_l:
            return key_l not in SAFE_KEY_ALLOWLIST and not key_l.endswith("_tokens")
    return False


def _scrub_string(
    text: str,
    *,
    path: str,
    redacted_paths: list[dict[str, str]] | None,
    value_patterns: tuple[str, ...],
) -> str:
    scrubbed = text
    for pattern in value_patterns:
        regex = _compiled_pattern(pattern)
        if regex.search(scrubbed):
            scrubbed, count = regex.subn("[REDACTED]", scrubbed)
            if count and redacted_paths is not None:
                redacted_paths.append({"path": path, "reason": f"value_pattern:{pattern}"})
    return scrubbed


def _redact_untracked(
    value: Any,
    key_fragments: tuple[str, ...],
    compiled: tuple["re.Pattern[str]", ...],
) -> Any:
    """`redact_value` without path bookkeeping. Same output; used when no redaction log is kept."""
    kind = type(value)
    if kind is str:
        for regex in compiled:
            if regex.search(value):
                value = regex.sub("[REDACTED]", value)
        return value
    if value is None or kind is int or kind is float or kind is bool:
        return value
    if kind is dict or isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for key, child in value.items():
            key_l = key.lower() if type(key) is str else str(key).lower()
            if _is_sensitive_key(key_l, key_fragments):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = _redact_untracked(child, key_fragments, compiled)
        return redacted
    if isinstance(value, list):
        return [_redact_untracked(child, key_fragments, compiled) for child in value]
    if isinstance(value, str):
        for regex in compiled:
            if regex.search(value):
                value = regex.sub("[REDACTED]", value)
        return value
    return value


def redact_value(
    value: Any,
    *,
    path: str = "",
    redacted_paths: list[dict[str, str]] | None = None,
    key_fragments: tuple[str, ...] = DEFAULT_REDACTION_KEYS,
    value_patterns: tuple[str, ...] = DEFAULT_VALUE_PATTERNS,
) -> Any:
    if type(key_fragments) is not tuple:
        key_fragments = tuple(key_fragments)
    if redacted_paths is None:
        compiled = tuple(_compiled_pattern(pattern) for pattern in value_patterns)
        return _redact_untracked(value, key_fragments, compiled)
    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            if _is_sensitive_key(str(key).lower(), key_fragments):
                redacted[key] = "[REDACTED]"
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


def resolve_redaction_rules(
    policy: Mapping[str, Any] | None,
    *,
    key_fragments: tuple[str, ...] | None = None,
    value_patterns: tuple[str, ...] | None = None,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    policy = policy or {}
    fragments = key_fragments or tuple(policy.get("key_fragments") or DEFAULT_REDACTION_KEYS)
    patterns = value_patterns or tuple(policy.get("value_patterns") or DEFAULT_VALUE_PATTERNS)
    return fragments, patterns


def redact_span(
    span: Any,
    *,
    key_fragments: tuple[str, ...],
    value_patterns: tuple[str, ...],
    base: str = "span",
    redacted_paths: list[dict[str, str]] | None = None,
) -> None:
    """Apply the redaction policy in place to every span field that can carry captured text.

    Identity fields (ids, type, status, timestamps, error.type) are left intact.
    """

    def value(v: Any, path: str) -> Any:
        return redact_value(
            v,
            path=path,
            redacted_paths=redacted_paths,
            key_fragments=key_fragments,
            value_patterns=value_patterns,
        )

    def text(v: str, path: str) -> str:
        return _scrub_string(v, path=path, redacted_paths=redacted_paths, value_patterns=value_patterns)

    span.inputs = value(span.inputs, f"{base}.inputs")
    span.outputs = value(span.outputs, f"{base}.outputs")
    span.attributes = value(span.attributes, f"{base}.attributes")
    span.data = value(span.data, f"{base}.data")
    span.events = [value(ev, f"{base}.events.{ei}") for ei, ev in enumerate(span.events or [])]
    if span.name:
        span.name = text(span.name, f"{base}.name") or span.name
    if span.failure_context:
        span.failure_context = text(span.failure_context, f"{base}.failure_context")
    if span.error is not None:
        span.error.message = text(span.error.message or "", f"{base}.error.message")
        if span.error.stack:
            span.error.stack = text(span.error.stack, f"{base}.error.stack")


def redact_bundle(
    bundle: IncidentBundle,
    *,
    key_fragments: tuple[str, ...] | None = None,
    value_patterns: tuple[str, ...] | None = None,
) -> IncidentBundle:
    fragments, patterns = resolve_redaction_rules(
        bundle.redaction_policy, key_fragments=key_fragments, value_patterns=value_patterns
    )
    # Bypass strict validation during clone of in-progress/raw bundles.
    # Spans are not deep-copied: `redact_span` below rebuilds every container they hold, so the
    # clone never shares a mutable container with the source. Everything else is deep-copied.
    raw = bundle.to_dict()
    span_dicts = raw.pop("spans")
    raw["audit"] = {"chain": [], "bundle_hash": ""}
    raw["audit_chain"] = []
    raw = copy.deepcopy(raw)
    raw["spans"] = span_dicts
    clone = IncidentBundle.from_dict(raw)
    redactions: list[dict[str, str]] = []
    clone.metadata = redact_value(
        clone.metadata,
        path="metadata",
        redacted_paths=redactions,
        key_fragments=fragments,
        value_patterns=patterns,
    )
    if clone.title:
        clone.title = _scrub_string(
            clone.title, path="title", redacted_paths=redactions, value_patterns=patterns
        ) or clone.title
    if isinstance(clone.root_cause_hint, str):
        clone.root_cause_hint = _scrub_string(
            clone.root_cause_hint, path="root_cause_hint", redacted_paths=redactions, value_patterns=patterns
        )
    for span_index, span in enumerate(clone.spans):
        redact_span(
            span,
            key_fragments=fragments,
            value_patterns=patterns,
            base=f"spans.{span_index}",
            redacted_paths=redactions,
        )
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


def require_normal_form(stored: Any, normalized: Any, what: str) -> None:
    """Fail closed unless the stored object is exactly the normalized one the hashes cover.

    Hashes are computed over the normalized form, so any stored difference (an unknown key, a
    missing default, a different JSON type) would otherwise be accepted without being bound.
    """
    from sage.errors import ChainIntegrityError

    if canonical_json(stored) == canonical_json(normalized):
        return
    field = "?"
    if isinstance(stored, dict) and isinstance(normalized, dict):
        for key in sorted(set(stored) | set(normalized)):
            if key not in stored or key not in normalized or canonical_json(stored[key]) != canonical_json(
                normalized[key]
            ):
                field = key
                break
    raise ChainIntegrityError(f"{what} is not in normal form (field {field!r}); stored content is not hash-bound")


def require_verified(bundle: IncidentBundle) -> IncidentBundle:
    from sage.concurrency import validate_monotonic_chain
    from sage.errors import AuditChainMismatchError

    bundle.validate(strict=True)
    verify_parent_integrity(bundle)
    validate_monotonic_chain(bundle)
    if not verify_audit_chain(bundle):
        raise AuditChainMismatchError("audit chain or bundle_hash verification failed")
    verify_parent_content_hashes(bundle)
    return bundle
