from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from sage.errors import ChainIntegrityError

POLICY_FORMAT = "sage.verify.policy.v1"


@dataclass
class VerifyPolicy:
    """Fail-closed evidence verification policy (sage.verify.policy.v1)."""

    format: str = POLICY_FORMAT
    policy_id: str = "default"
    require_sealed: bool = True
    forbid_live_journal: bool = True
    require_witness: bool = False
    require_witness_hmac: bool = False
    require_pack_hmac: bool = False
    require_pack_v2: bool = False
    require_pack_signature: bool = False
    require_blob_inventory: bool = True
    min_redaction_count: int = 0
    min_span_count: int = 0
    allowed_kinds: list[str] = field(default_factory=lambda: ["bundle", "journal", "pack"])

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def digest(self) -> str:
        return hashlib.sha256(
            json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()


def load_policy(source: str | Path | dict[str, Any] | None = None) -> VerifyPolicy:
    if source is None:
        env = os.environ.get("SAGE_VERIFY_POLICY")
        if env and Path(env).exists():
            source = env
        else:
            return VerifyPolicy()
    if isinstance(source, dict):
        data = source
    else:
        data = json.loads(Path(source).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ChainIntegrityError("policy must be a JSON object")
    known = set(VerifyPolicy.__dataclass_fields__.keys())  # type: ignore[attr-defined]
    unknown = sorted(set(data.keys()) - known)
    if unknown:
        raise ChainIntegrityError(f"policy has unknown fields: {unknown}")
    fmt = data.get("format", POLICY_FORMAT)
    if fmt != POLICY_FORMAT:
        raise ChainIntegrityError(f"unsupported policy format: {fmt!r}")
    # Type checks for booleans / ints / lists.
    bool_fields = {
        "require_sealed",
        "forbid_live_journal",
        "require_witness",
        "require_witness_hmac",
        "require_pack_hmac",
        "require_pack_v2",
        "require_pack_signature",
        "require_blob_inventory",
    }
    for name in bool_fields:
        if name in data and not isinstance(data[name], bool):
            raise ChainIntegrityError(f"policy field {name} must be bool")
    for name in ("min_redaction_count", "min_span_count"):
        if name in data and (not isinstance(data[name], int) or isinstance(data[name], bool)):
            raise ChainIntegrityError(f"policy field {name} must be int")
    if "allowed_kinds" in data and not isinstance(data["allowed_kinds"], list):
        raise ChainIntegrityError("policy field allowed_kinds must be list")
    kwargs = {k: v for k, v in data.items() if k in known}
    policy = VerifyPolicy(**kwargs)
    if policy.require_witness_hmac and not policy.require_witness:
        # HMAC implies witness presence.
        policy.require_witness = True
    if policy.require_pack_v2 and not policy.require_pack_hmac:
        # v2 without HMAC is meaningless for custody.
        pass
    return policy


def apply_policy(report: dict[str, Any], policy: VerifyPolicy) -> list[str]:
    """Return policy_violations (empty = pass). Mutates report with policy metadata."""
    violations: list[str] = []
    kind = str(report.get("kind") or "")
    if policy.allowed_kinds and kind not in policy.allowed_kinds:
        violations.append(f"kind {kind!r} not in allowed_kinds={policy.allowed_kinds}")
    if report.get("live") and (policy.forbid_live_journal or policy.require_sealed):
        violations.append("live journal forbidden by policy")
    if policy.require_witness or policy.require_witness_hmac:
        wit = report.get("witness")
        if not wit:
            violations.append("witness required by policy but missing/not checked")
        elif policy.require_witness_hmac and not wit.get("hmac_verified"):
            violations.append("witness HMAC required by policy")
    if policy.require_pack_hmac and kind == "pack":
        pack = report.get("pack") or {}
        att = pack.get("attestation") or {}
        if not att.get("mac"):
            violations.append("pack HMAC required by policy")
        if not report.get("pack_hmac_verified"):
            violations.append("pack HMAC not verified (missing key?)")
    if policy.require_pack_v2 and kind == "pack":
        fmt = str((report.get("pack") or {}).get("format") or "")
        ver = ((report.get("pack") or {}).get("attestation") or {}).get("version")
        if fmt != "sage.pack.v2" and ver != 2:
            violations.append("pack attestation v2 required by policy")
    if policy.require_pack_signature and kind == "pack":
        pack = report.get("pack") or {}
        if not (pack.get("signature") or {}).get("sig"):
            violations.append("pack Ed25519 signature required by policy")
        elif not report.get("pack_signature_pinned"):
            violations.append("pack signature pin verify required by policy")
    if policy.require_blob_inventory:
        blobs = report.get("blobs")
        if blobs is None and report.get("live"):
            pass
        elif blobs is None:
            violations.append("blob inventory required by policy but not run")
    if policy.min_span_count:
        count = int(report.get("span_count") or (report.get("journal") or {}).get("span_count") or 0)
        if count < policy.min_span_count:
            violations.append(f"span_count {count} < min_span_count {policy.min_span_count}")
    if policy.min_redaction_count:
        summary = (report.get("pack") or {}).get("redaction_summary") or {}
        count = int(summary.get("redaction_count") or report.get("redaction_count") or 0)
        if count < policy.min_redaction_count:
            violations.append(
                f"redaction_count {count} < min_redaction_count {policy.min_redaction_count}"
            )
    report["policy"] = {
        "policy_id": policy.policy_id,
        "policy_digest": policy.digest(),
        "violations": violations,
    }
    if violations:
        report["ok"] = False
        raise ChainIntegrityError("policy violations: " + "; ".join(violations))
    return violations
