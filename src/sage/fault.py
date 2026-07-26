from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sage.audit import build_audit_chain, sha256_digest
from sage.errors import FaultRecoveryError
from sage.schema import AuditBlock, IncidentBundle, SCHEMA_VERSION


@dataclass
class CrashBoundary:
    last_valid_chain_index: int
    last_valid_hash: str
    recovered_span_count: int
    truncated: bool
    failure_anchor: dict[str, Any]
    rejected_tail_bytes: int = 0


@dataclass
class RecoveryReport:
    ok: bool
    path: str
    boundary: CrashBoundary | None
    bundle: IncidentBundle | None = None
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "path": self.path,
            "errors": self.errors,
            "boundary": None
            if self.boundary is None
            else {
                "last_valid_chain_index": self.boundary.last_valid_chain_index,
                "last_valid_hash": self.boundary.last_valid_hash,
                "recovered_span_count": self.boundary.recovered_span_count,
                "truncated": self.boundary.truncated,
                "failure_anchor": self.boundary.failure_anchor,
                "rejected_tail_bytes": self.boundary.rejected_tail_bytes,
            },
            "bundle_id": self.bundle.bundle_id if self.bundle else None,
            "status": self.bundle.status if self.bundle else None,
        }


_SPAN_OBJECT_RE = re.compile(
    r'\{\s*"span_id"\s*:\s*"(span_[^"]+|[^"]+)"\s*,.*?\n\s*\}',
    re.DOTALL,
)


def _extract_balanced_objects(array_text: str) -> list[str]:
    """Extract complete top-level JSON objects from a possibly truncated array body."""
    objects: list[str] = []
    depth = 0
    start = -1
    in_string = False
    escape = False
    for i, ch in enumerate(array_text):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            continue
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                objects.append(array_text[start : i + 1])
                start = -1
            if depth < 0:
                break
    return objects


def _extract_spans_prefix(raw: str) -> tuple[list[dict[str, Any]], int]:
    marker = '"spans"'
    idx = raw.find(marker)
    if idx < 0:
        return [], 0
    bracket = raw.find("[", idx)
    if bracket < 0:
        return [], 0
    body = raw[bracket + 1 :]
    chunks = _extract_balanced_objects(body)
    spans: list[dict[str, Any]] = []
    consumed = bracket + 1
    for chunk in chunks:
        try:
            spans.append(json.loads(chunk))
            consumed = raw.find(chunk, consumed) + len(chunk)
        except json.JSONDecodeError:
            break
    return spans, max(0, len(raw) - consumed)


def _extract_header_fields(raw: str) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for key in ("schema_version", "bundle_id", "title", "created_at", "status"):
        m = re.search(rf'"{key}"\s*:\s*"([^"]*)"', raw)
        if m:
            fields[key] = m.group(1)
    run = re.search(r'"run_id"\s*:\s*"([^"]*)"', raw)
    framework = re.search(r'"framework"\s*:\s*"([^"]*)"', raw)
    fields["source"] = {
        "framework": framework.group(1) if framework else "custom",
        "run_id": run.group(1) if run else "recovered-run",
        "environment": "fault-recovery",
    }
    return fields


def recover_bundle_carcass(path: str | Path) -> RecoveryReport:
    """Best-effort recovery of a truncated / power-failed bundle file.

    Never raises into a traceback for truncated JSON: returns a structured report.
    Inspect/audit callers should treat ok=False as fail-closed rejection of the tail.
    """
    file_path = Path(path)
    try:
        raw = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return RecoveryReport(ok=False, path=str(file_path), boundary=None, errors=[str(exc)])

    # Happy path: intact JSON.
    try:
        data = json.loads(raw)
        bundle = IncidentBundle.from_dict(data)
        chain = bundle.audit.chain or build_audit_chain(bundle)
        last_hash = chain[-1]["hash"] if chain else ("0" * 64)
        boundary = CrashBoundary(
            last_valid_chain_index=len(chain) - 1,
            last_valid_hash=last_hash,
            recovered_span_count=len(bundle.spans),
            truncated=False,
            failure_anchor={"kind": "intact", "message": "no crash boundary"},
            rejected_tail_bytes=0,
        )
        return RecoveryReport(ok=True, path=str(file_path), boundary=boundary, bundle=bundle)
    except Exception:
        pass

    spans, rejected = _extract_spans_prefix(raw)
    header = _extract_header_fields(raw)
    if not spans:
        return RecoveryReport(
            ok=False,
            path=str(file_path),
            boundary=CrashBoundary(
                last_valid_chain_index=-1,
                last_valid_hash="0" * 64,
                recovered_span_count=0,
                truncated=True,
                failure_anchor={
                    "kind": "crash_boundary",
                    "message": "no recoverable span objects before truncation",
                    "byte_offset": 0,
                },
                rejected_tail_bytes=len(raw),
            ),
            errors=["uncorrupted prefix contains zero complete spans"],
        )

    # Rebuild a partial bundle and compute chain only over recovered spans.
    partial = {
        "schema_version": header.get("schema_version") or SCHEMA_VERSION,
        "bundle_id": header.get("bundle_id") or "bundle_recovered",
        "title": header.get("title") or "fault-recovered",
        "created_at": header.get("created_at") or "1970-01-01T00:00:00+00:00",
        "source": header.get("source"),
        "status": "partial",
        "root_cause_hint": None,
        "metadata": {
            "fault_recovery": True,
            "crash_boundary": True,
            "rejected_tail_bytes": rejected,
        },
        "spans": spans,
        "redactions": [],
        "redaction_policy": {},
        "audit": {"chain": [], "bundle_hash": ""},
    }
    try:
        # Soft-load: skip strict typed validation for truncated carcass spans.
        from sage.schema import SageSpan, BundleSource, utc_now

        bundle = IncidentBundle(
            title=str(partial["title"]),
            bundle_id=str(partial["bundle_id"]),
            schema_version=SCHEMA_VERSION,
            created_at=str(partial["created_at"]),
            source=BundleSource(**partial["source"]),
            status="partial",
            metadata=partial["metadata"],
        )
        for raw_span in spans:
            try:
                span = SageSpan.from_dict(raw_span, default_trace_id=bundle.bundle_id)
                if not span.trace_id:
                    span.trace_id = bundle.bundle_id
                if not span.end_time:
                    span.end_time = span.start_time or utc_now()
                bundle.spans.append(span)
            except Exception:
                # Drop incomplete span object at the crash edge.
                break
        if not bundle.spans:
            raise FaultRecoveryError("all candidate spans failed soft-parse")
        chain = build_audit_chain(bundle)
        bundle.audit = AuditBlock(chain=chain, bundle_hash="")
        # Anchor hash of recovered prefix (not a full verified bundle_hash).
        prefix_hash = sha256_digest(
            {"bundle_id": bundle.bundle_id, "spans": [s.span_id for s in bundle.spans], "chain": chain}
        )
        bundle.audit.bundle_hash = ""
        bundle.metadata["failure_anchor"] = {
            "kind": "crash_boundary",
            "message": "unexpected crash / truncated write detected",
            "last_valid_hash": chain[-1]["hash"] if chain else "0" * 64,
            "last_valid_chain_index": len(chain) - 1,
            "prefix_hash": prefix_hash,
            "rejected_tail_bytes": rejected,
        }
        boundary = CrashBoundary(
            last_valid_chain_index=len(chain) - 1,
            last_valid_hash=chain[-1]["hash"] if chain else "0" * 64,
            recovered_span_count=len(bundle.spans),
            truncated=True,
            failure_anchor=bundle.metadata["failure_anchor"],
            rejected_tail_bytes=rejected,
        )
        # Recovered carcass is NEVER verification-ok; inspect must reject full trust.
        return RecoveryReport(
            ok=False,
            path=str(file_path),
            boundary=boundary,
            bundle=bundle,
            errors=["truncated carcass: recovered prefix only; refuse full verification"],
        )
    except Exception as exc:
        return RecoveryReport(
            ok=False,
            path=str(file_path),
            boundary=None,
            errors=[f"fault recovery failed closed: {exc}"],
        )


def audit_path(path: str | Path) -> RecoveryReport:
    """CLI-facing audit: verified intact bundle or structured crash-boundary report."""
    from sage.audit import require_verified
    from sage.bundle_io import load_bundle
    from sage.journal import is_journal_path, recover_journal

    file_path = Path(path)
    try:
        bundle = load_bundle(file_path, verify=True, rehydrate=False)
        require_verified(bundle)
        chain = bundle.audit.chain
        return RecoveryReport(
            ok=True,
            path=str(file_path),
            boundary=CrashBoundary(
                last_valid_chain_index=len(chain) - 1,
                last_valid_hash=chain[-1]["hash"] if chain else bundle.audit.bundle_hash,
                recovered_span_count=len(bundle.spans),
                truncated=False,
                failure_anchor={"kind": "verified", "bundle_hash": bundle.audit.bundle_hash},
            ),
            bundle=bundle,
        )
    except Exception:
        if is_journal_path(file_path):
            return recover_journal(file_path)
        return recover_bundle_carcass(file_path)
