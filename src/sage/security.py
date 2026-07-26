from __future__ import annotations

from typing import Any

from sage.errors import SecurityDivergence
from sage.schema import IncidentBundle


def _span_layout(bundle: IncidentBundle) -> dict[str, dict[str, Any]]:
    return {
        span.span_id: {
            "parent_id": span.parent_id,
            "type": span.type,
            "name": span.name,
            "agent_id": span.agent_id,
        }
        for span in bundle.spans
    }


def _find_policy_guardrail(bundle: IncidentBundle) -> tuple[str | None, str | None]:
    policy = next((s.span_id for s in bundle.spans if s.type == "policy"), None)
    guard = next((s.span_id for s in bundle.spans if s.type == "guardrail"), None)
    return policy, guard


def validate_heal_boundary(
    original: IncidentBundle,
    healed: IncidentBundle,
    *,
    heal_span_id: str,
    allow_secondary_failure: bool = True,
) -> None:
    """Fail-closed security checks for --with-heal / write_heal_boundary_test.

    Detects:
    - injected dummy spans (new span_ids)
    - falsified parent_id edges
    - telemetry layout mutations unrelated to the heal target / secondary mutations
    - missing heal provenance metadata
    """
    policy_id, guard_id = _find_policy_guardrail(original)
    orig_ids = {s.span_id for s in original.spans}
    heal_ids = {s.span_id for s in healed.spans}

    injected = sorted(heal_ids - orig_ids)
    if injected:
        raise SecurityDivergence(
            f"heal path injected unauthorized span_ids: {injected}",
            policy_span_id=policy_id,
            guardrail_span_id=guard_id,
            details={"injected_span_ids": injected, "heal_span_id": heal_span_id},
        )

    missing = sorted(orig_ids - heal_ids)
    if missing:
        raise SecurityDivergence(
            f"heal path dropped original span_ids: {missing}",
            policy_span_id=policy_id,
            guardrail_span_id=guard_id,
            details={"missing_span_ids": missing, "heal_span_id": heal_span_id},
        )

    orig_layout = _span_layout(original)
    heal_layout = _span_layout(healed)
    parent_tamper: list[dict[str, Any]] = []
    type_tamper: list[dict[str, Any]] = []
    for span_id, before in orig_layout.items():
        after = heal_layout[span_id]
        if before["parent_id"] != after["parent_id"]:
            parent_tamper.append(
                {
                    "span_id": span_id,
                    "original_parent_id": before["parent_id"],
                    "healed_parent_id": after["parent_id"],
                }
            )
        if before["type"] != after["type"] or before["name"] != after["name"]:
            type_tamper.append({"span_id": span_id, "before": before, "after": after})

    if parent_tamper:
        raise SecurityDivergence(
            "heal path falsified parent_id graph (SecurityDivergence)",
            policy_span_id=policy_id,
            guardrail_span_id=guard_id,
            details={"parent_tamper": parent_tamper, "heal_span_id": heal_span_id},
        )
    if type_tamper:
        raise SecurityDivergence(
            "heal path mutated immutable telemetry layout",
            policy_span_id=policy_id,
            guardrail_span_id=guard_id,
            details={"layout_tamper": type_tamper, "heal_span_id": heal_span_id},
        )

    meta = healed.metadata or {}
    if meta.get("healed_from_bundle_id") != original.bundle_id:
        raise SecurityDivergence(
            "healed bundle missing/invalid healed_from_bundle_id provenance",
            policy_span_id=policy_id,
            guardrail_span_id=guard_id,
            details={"metadata": dict(meta)},
        )
    if meta.get("healed_span_id") != heal_span_id:
        raise SecurityDivergence(
            "healed_span_id does not match requested heal target",
            policy_span_id=policy_id,
            guardrail_span_id=guard_id,
            details={"expected": heal_span_id, "got": meta.get("healed_span_id")},
        )

    # Sealed capability must be present and valid; patch mutations ⊆ capability.
    from sage.heal_capability import HealCapability, HealPatch

    raw_cap = meta.get("heal_capability")
    if not isinstance(raw_cap, dict):
        raise SecurityDivergence(
            "healed bundle missing sealed heal_capability",
            policy_span_id=policy_id,
            guardrail_span_id=guard_id,
        )
    try:
        cap = HealCapability.from_dict(raw_cap)
    except SecurityDivergence:
        raise
    except Exception as exc:
        raise SecurityDivergence(
            f"heal_capability unreadable: {exc}",
            policy_span_id=policy_id,
            guardrail_span_id=guard_id,
        ) from exc
    if heal_span_id not in cap.allowed_span_ids:
        raise SecurityDivergence(
            "heal_span_id outside sealed capability",
            policy_span_id=policy_id,
            guardrail_span_id=guard_id,
            details={"allowed": cap.allowed_span_ids, "heal_span_id": heal_span_id},
        )
    if cap.source_bundle_id != original.bundle_id:
        raise SecurityDivergence(
            "heal capability source_bundle_id mismatch",
            policy_span_id=policy_id,
            guardrail_span_id=guard_id,
            details={"expected": original.bundle_id, "got": cap.source_bundle_id},
        )
    if cap.source_bundle_hash and cap.source_bundle_hash != original.audit.bundle_hash:
        raise SecurityDivergence(
            "heal capability source_bundle_hash mismatch",
            policy_span_id=policy_id,
            guardrail_span_id=guard_id,
            details={"expected": original.audit.bundle_hash, "got": cap.source_bundle_hash},
        )
    raw_patch = meta.get("heal_patch")
    if isinstance(raw_patch, dict):
        HealPatch(
            capability=cap,
            primary_span_id=str(raw_patch.get("primary_span_id") or heal_span_id),
            mutations=list(raw_patch.get("mutations") or []),
        ).validate()

    # Non-deterministic layout: span order permutation with identical IDs but reordered
    # emission that breaks parent-before-child seq if present.
    from sage.concurrency import validate_monotonic_chain
    from sage.errors import ChainIntegrityError

    try:
        validate_monotonic_chain(healed)
    except ChainIntegrityError as exc:
        raise SecurityDivergence(
            f"healed execution chain failed monotonic validation: {exc}",
            policy_span_id=policy_id,
            guardrail_span_id=guard_id,
            details={"heal_span_id": heal_span_id},
        ) from exc

    if healed.status == "failed" and not allow_secondary_failure:
        raise SecurityDivergence(
            "healed path remained failed without secondary_failure allowance",
            policy_span_id=policy_id,
            guardrail_span_id=guard_id,
        )


def assert_heal_not_adversarial(
    original: IncidentBundle,
    candidate_patch: dict[str, Any],
) -> None:
    """Inspect a simulated rogue patch dict before it is applied."""
    policy_id, guard_id = _find_policy_guardrail(original)
    if candidate_patch.get("inject_spans"):
        raise SecurityDivergence(
            "rogue patch attempted dummy span injection",
            policy_span_id=policy_id,
            guardrail_span_id=guard_id,
            details={"patch": candidate_patch},
        )
    if candidate_patch.get("falsify_parent_id") or candidate_patch.get("rewrite_parents"):
        raise SecurityDivergence(
            "rogue patch attempted parent_id falsification",
            policy_span_id=policy_id,
            guardrail_span_id=guard_id,
            details={"patch": candidate_patch},
        )
    if candidate_patch.get("bypass_validation") or candidate_patch.get("skip_audit"):
        raise SecurityDivergence(
            "rogue patch attempted validation bypass",
            policy_span_id=policy_id,
            guardrail_span_id=guard_id,
            details={"patch": candidate_patch},
        )
