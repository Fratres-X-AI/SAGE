from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from typing import Any

from sage.errors import SecurityDivergence
from sage.schema import IncidentBundle, new_id, utc_now

ALLOWED_HEAL_FIELDS = frozenset(
    {"status", "error", "outputs", "data", "inputs", "is_suspected_root_cause", "failure_context"}
)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def capability_digest(payload: dict[str, Any]) -> str:
    body = {k: v for k, v in payload.items() if k not in {"seal", "mac"}}
    return hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()


def _heal_key() -> bytes | None:
    raw = os.environ.get("SAGE_HEAL_KEY") or os.environ.get("SAGE_PACK_KEY")
    return raw.encode("utf-8") if raw else None


def capability_mac(payload: dict[str, Any], key: bytes | str) -> str:
    # MAC binds seal + authority fields (everything except mac itself).
    body = {k: v for k, v in payload.items() if k != "mac"}
    raw = key.encode("utf-8") if isinstance(key, str) else key
    return hmac.new(raw, _canonical(body).encode("utf-8"), hashlib.sha256).hexdigest()


@dataclass
class HealCapability:
    """Scoped, sealed permission for a heal / make-test mutation.

    Seal is content hash over capability fields including source_bundle_hash.
    When SAGE_HEAL_KEY / SAGE_PACK_KEY is set, mac is also required (keyed attestation).
    """

    capability_id: str
    source_bundle_id: str
    source_bundle_hash: str
    allowed_span_ids: list[str]
    allowed_fields: list[str] = field(default_factory=lambda: sorted(ALLOWED_HEAL_FIELDS))
    allow_secondary_failure: bool = True
    allow_cascade: bool = True
    issued_at: str = field(default_factory=utc_now)
    seal: str = ""
    mac: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "source_bundle_id": self.source_bundle_id,
            "source_bundle_hash": self.source_bundle_hash,
            "allowed_span_ids": list(self.allowed_span_ids),
            "allowed_fields": list(self.allowed_fields),
            "allow_secondary_failure": self.allow_secondary_failure,
            "allow_cascade": self.allow_cascade,
            "issued_at": self.issued_at,
            "seal": self.seal,
            "mac": self.mac,
        }

    @classmethod
    def issue(
        cls,
        bundle: IncidentBundle,
        *,
        heal_span_id: str,
        extra_span_ids: list[str] | None = None,
        allow_secondary_failure: bool = True,
        allow_cascade: bool = True,
    ) -> "HealCapability":
        allowed = sorted({heal_span_id, *(extra_span_ids or [])})
        unknown = [sid for sid in allowed if sid not in {s.span_id for s in bundle.spans}]
        if unknown:
            raise SecurityDivergence(
                f"capability references unknown span_ids: {unknown}",
                details={"unknown": unknown},
            )
        source_hash = str(bundle.audit.bundle_hash or "")
        if not source_hash:
            raise SecurityDivergence(
                "cannot issue heal capability: source bundle missing bundle_hash (finalize first)"
            )
        cap = cls(
            capability_id=new_id("healcap"),
            source_bundle_id=bundle.bundle_id,
            source_bundle_hash=source_hash,
            allowed_span_ids=allowed,
            allow_secondary_failure=allow_secondary_failure,
            allow_cascade=allow_cascade,
        )
        payload = cap.to_dict()
        cap.seal = capability_digest(payload)
        key = _heal_key()
        if key is not None:
            cap.mac = capability_mac({**payload, "seal": cap.seal}, key)
        return cap

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, require_mac: bool | None = None) -> "HealCapability":
        cap = cls(
            capability_id=str(data["capability_id"]),
            source_bundle_id=str(data["source_bundle_id"]),
            source_bundle_hash=str(data.get("source_bundle_hash") or ""),
            allowed_span_ids=list(data.get("allowed_span_ids") or []),
            allowed_fields=list(data.get("allowed_fields") or sorted(ALLOWED_HEAL_FIELDS)),
            allow_secondary_failure=bool(data.get("allow_secondary_failure", True)),
            allow_cascade=bool(data.get("allow_cascade", True)),
            issued_at=str(data.get("issued_at") or utc_now()),
            seal=str(data.get("seal") or ""),
            mac=str(data.get("mac") or ""),
        )
        if not cap.source_bundle_hash:
            raise SecurityDivergence(
                "heal capability missing source_bundle_hash (forged or pre-2.0.1 capability)"
            )
        expected = capability_digest(cap.to_dict())
        if not cap.seal or cap.seal != expected:
            raise SecurityDivergence(
                "heal capability seal mismatch (tampered or forged capability)",
                details={"expected": expected, "got": cap.seal},
            )
        key = _heal_key()
        must_mac = require_mac if require_mac is not None else key is not None
        if must_mac:
            if key is None:
                raise SecurityDivergence("heal capability MAC required but no SAGE_HEAL_KEY/SAGE_PACK_KEY")
            expected_mac = capability_mac(cap.to_dict(), key)
            if not cap.mac or not hmac.compare_digest(cap.mac, expected_mac):
                raise SecurityDivergence(
                    "heal capability MAC mismatch (keyed attestation failed)",
                    details={"expected": expected_mac, "got": cap.mac},
                )
        return cap

    def assert_allows(self, *, span_id: str, fields: set[str]) -> None:
        if span_id not in self.allowed_span_ids:
            raise SecurityDivergence(
                f"heal capability does not allow span_id={span_id}",
                details={"allowed_span_ids": self.allowed_span_ids, "span_id": span_id},
            )
        illegal = sorted(fields - set(self.allowed_fields))
        if illegal:
            raise SecurityDivergence(
                f"heal capability forbids fields: {illegal}",
                details={"illegal_fields": illegal, "span_id": span_id},
            )


@dataclass
class HealPatch:
    """Concrete mutations constrained by a sealed HealCapability."""

    capability: HealCapability
    primary_span_id: str
    mutations: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability.to_dict(),
            "primary_span_id": self.primary_span_id,
            "mutations": self.mutations,
        }

    def validate(self) -> None:
        HealCapability.from_dict(self.capability.to_dict())
        if self.primary_span_id not in self.capability.allowed_span_ids:
            raise SecurityDivergence(
                "primary heal span not in capability",
                details={"primary_span_id": self.primary_span_id},
            )
        for mutation in self.mutations:
            span_id = str(mutation.get("span_id") or "")
            fields = {k for k in mutation if k != "span_id"}
            self.capability.assert_allows(span_id=span_id, fields=fields)


def _cascade_candidates(bundle: IncidentBundle, heal_span_id: str) -> list[str]:
    healed = next((s for s in bundle.spans if s.span_id == heal_span_id), None)
    if healed is None or healed.type not in {"retrieval", "llm"}:
        return []
    out: list[str] = []
    for later in bundle.spans:
        if later.start_time >= healed.start_time and later.status == "error":
            msg = (later.error.message if later.error else "").lower()
            if "schema" in msg or "stale" in msg or later.type == "tool":
                out.append(later.span_id)
        if later.type == "agent" and later.status == "error":
            out.append(later.span_id)
    return out


def issue_heal_patch(
    bundle: IncidentBundle,
    *,
    heal_span_id: str,
    new_output: dict[str, Any] | None = None,
    new_data: dict[str, Any] | None = None,
    secondary_mutations: list[dict[str, Any]] | None = None,
    status: str = "ok",
    cascade: bool = True,
) -> HealPatch:
    extras = [m["span_id"] for m in (secondary_mutations or []) if "span_id" in m]
    if cascade:
        extras.extend(_cascade_candidates(bundle, heal_span_id))
    cap = HealCapability.issue(
        bundle,
        heal_span_id=heal_span_id,
        extra_span_ids=extras,
        allow_secondary_failure=bool(secondary_mutations),
        allow_cascade=cascade,
    )
    primary: dict[str, Any] = {"span_id": heal_span_id, "status": status, "error": None}
    if new_output is not None:
        primary["outputs"] = new_output
    if new_data is not None:
        primary["data"] = new_data
    mutations = [primary, *(secondary_mutations or [])]
    patch = HealPatch(capability=cap, primary_span_id=heal_span_id, mutations=mutations)
    patch.validate()
    return patch
