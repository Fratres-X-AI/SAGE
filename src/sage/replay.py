from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable

from sage.diff import DivergenceReport, diff_bundles
from sage.schema import IncidentBundle, SageSpan, ensure_typed_data

ReplayHandler = Callable[[SageSpan], dict[str, Any] | None]
REPLAYABLE_TYPES = frozenset({"llm", "tool", "retrieval"})


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _span_signature(span: SageSpan) -> str:
    payload = {
        "type": span.type,
        "name": span.name,
        "inputs": span.inputs,
        "data_input": span.data.get("input") if span.type != "retrieval" else span.data.get("query"),
        "attributes": {k: v for k, v in span.attributes.items() if k != "usage"},
    }
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


@dataclass
class ReplayDivergence:
    """Legacy coarse divergence retained for compatibility."""

    span_id: str
    span_name: str
    kind: str
    reason: str
    expected: Any = None
    actual: Any = None


@dataclass
class ReplayResult:
    ok: bool
    final_status: str
    error_message: str | None = None
    matched: int = 0
    divergences: list[ReplayDivergence] = field(default_factory=list)
    report: DivergenceReport | None = None
    bundle: IncidentBundle | None = None

    def get_span(self, span_id: str) -> SageSpan | None:
        if not self.bundle:
            return None
        for span in self.bundle.spans:
            if span.span_id == span_id:
                return span
        return None


@dataclass
class ReplayCassette:
    """Deterministic lookup table built from a recorded incident bundle."""

    bundle: IncidentBundle
    _by_signature: dict[str, SageSpan] = field(default_factory=dict, init=False)
    _by_order: list[SageSpan] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        for span in self.bundle.spans:
            if span.type in REPLAYABLE_TYPES or span.kind in {"LLM", "TOOL", "RETRIEVER"}:
                self._by_signature[_span_signature(span)] = span
                self._by_order.append(span)

    def lookup(self, span: SageSpan) -> SageSpan | None:
        return self._by_signature.get(_span_signature(span))

    def lookup_by_index(self, index: int) -> SageSpan | None:
        if 0 <= index < len(self._by_order):
            return self._by_order[index]
        return None

    @classmethod
    def from_bundle(cls, bundle: IncidentBundle) -> "ReplayCassette":
        return cls(bundle=bundle)


def pure_recorded_replay(bundle: IncidentBundle) -> ReplayResult:
    """Reconstruct the recorded run from cassette outputs (no live calls)."""
    clone = IncidentBundle.from_dict(copy.deepcopy(bundle.to_dict()))
    # Outputs already present; ensure typed data and recompute failure signature.
    for span in clone.spans:
        ensure_typed_data(span)
    error_message = None
    for span in clone.spans:
        if span.status == "error" and span.error:
            error_message = span.error.message
            break
    report = diff_bundles(bundle, clone)
    return ReplayResult(
        ok=report.ok and clone.status in {"failed", "completed", "partial"},
        final_status=clone.status,
        error_message=error_message,
        matched=report.matched_span_count,
        divergences=[],
        report=report,
        bundle=clone,
    )


def replay_bundle(
    recorded: IncidentBundle,
    candidate_spans: list[SageSpan] | None = None,
    *,
    strict: bool = True,
    handler: ReplayHandler | None = None,
    live_tools: bool = False,
    candidate_bundle: IncidentBundle | None = None,
) -> ReplayResult:
    """Compare a candidate run against a recorded bundle.

    Default forensic mode is pure recorded replay when candidate_spans is None.
    Hybrid live tool execution is opt-in via live_tools and is not used by CLI default.
    """
    if candidate_spans is None and candidate_bundle is None:
        return pure_recorded_replay(recorded)

    if live_tools:
        # Explicit non-default mode flag for future controlled experiments.
        pass

    if candidate_bundle is None:
        candidate_bundle = IncidentBundle(
            title=f"candidate-of-{recorded.bundle_id}",
            spans=list(candidate_spans or []),
        )
        for span in candidate_bundle.spans:
            if not span.trace_id:
                span.trace_id = candidate_bundle.bundle_id
            ensure_typed_data(span)

    overlaid = IncidentBundle.from_dict(copy.deepcopy(candidate_bundle.to_dict()))
    # Only apply cassette overlays when an explicit handler is provided.
    # Candidate comparison must preserve actual candidate outputs.
    if handler is not None:
        replayable = [s for s in overlaid.spans if s.type in REPLAYABLE_TYPES]
        for span in replayable:
            patched = handler(span)
            if patched is not None:
                span.outputs = {**span.outputs, **patched}
                span.data["output"] = span.outputs

    report = diff_bundles(recorded, overlaid)
    coarse: list[ReplayDivergence] = []
    for item in report.divergences:
        coarse.append(
            ReplayDivergence(
                span_id=item.span_id,
                span_name=item.span_name,
                kind=item.span_type,
                reason=item.reason,
                expected=item.field_diffs[0].expected if item.field_diffs else None,
                actual=item.field_diffs[0].actual if item.field_diffs else None,
            )
        )

    error_message = None
    for span in overlaid.spans:
        if span.status == "error" and span.error:
            error_message = span.error.message
            break

    ok = report.ok if strict else report.divergent_span_count == 0
    return ReplayResult(
        ok=ok,
        final_status=overlaid.status,
        error_message=error_message,
        matched=report.matched_span_count,
        divergences=coarse,
        report=report,
        bundle=overlaid,
    )


def apply_heal(
    bundle: IncidentBundle,
    *,
    span_id: str,
    new_output: dict[str, Any] | None = None,
    new_data: dict[str, Any] | None = None,
    status: str = "ok",
    cascade: bool = True,
    secondary_mutations: list[dict[str, Any]] | None = None,
    patch: Any | None = None,
    require_capability: bool = True,
) -> IncidentBundle:
    """Return a copy with one span healed for counterfactual experiments.

    When require_capability=True (default), a sealed HealCapability/HealPatch is
    issued or validated before mutations apply. Escaping the capability scope
    raises SecurityDivergence.
    """
    from sage.audit import finalize_bundle
    from sage.heal_capability import HealPatch, issue_heal_patch
    from sage.schema import SpanError

    if patch is None:
        patch = issue_heal_patch(
            bundle,
            heal_span_id=span_id,
            new_output=new_output,
            new_data=new_data,
            secondary_mutations=secondary_mutations,
            status=status,
            cascade=cascade,
        )
    elif not isinstance(patch, HealPatch):
        raise TypeError("patch must be a HealPatch")
    if require_capability:
        patch.validate()
        if not patch.capability.allow_cascade:
            cascade = False

    clone = IncidentBundle.from_dict(copy.deepcopy(bundle.to_dict()))
    found = False
    for span in clone.spans:
        if span.span_id != span_id:
            continue
        found = True
        span.status = status  # type: ignore[assignment]
        span.error = None
        span.is_suspected_root_cause = False
        if new_output is not None:
            span.outputs = new_output
            span.data["output"] = new_output
        if new_data is not None:
            span.data.update(new_data)
        if span.type == "tool":
            span.data["success"] = status == "ok"
        if span.type == "retrieval" and new_data and "documents" in new_data:
            span.outputs["documents"] = new_data["documents"]
        ensure_typed_data(span)
    if not found:
        raise KeyError(f"span_id not found: {span_id}")

    healed = next(s for s in clone.spans if s.span_id == span_id)
    from sage.errors import SecurityDivergence

    if cascade and healed.type in {"retrieval", "llm"}:
        for later in clone.spans:
            if later.start_time >= healed.start_time and later.status == "error":
                msg = (later.error.message if later.error else "").lower()
                if "schema" in msg or "stale" in msg or later.type == "tool":
                    if require_capability and later.span_id not in patch.capability.allowed_span_ids:
                        raise SecurityDivergence(
                            f"heal cascade target outside sealed capability: {later.span_id}",
                            details={
                                "span_id": later.span_id,
                                "allowed_span_ids": patch.capability.allowed_span_ids,
                            },
                        )
                    later.status = "ok"
                    later.error = None
                    later.outputs = {"result": "ok", "repaired": True}
                    later.data["output"] = later.outputs
                    if later.type == "tool":
                        later.data["success"] = True

    for mutation in secondary_mutations or []:
        target_id = mutation["span_id"]
        if require_capability:
            fields = {k for k in mutation if k != "span_id"}
            patch.capability.assert_allows(span_id=target_id, fields=fields)
        for span in clone.spans:
            if span.span_id != target_id:
                continue
            if "status" in mutation:
                span.status = mutation["status"]  # type: ignore[assignment]
            if "error" in mutation:
                span.error = SpanError.from_value(mutation["error"])
                span.status = "error"
            if "outputs" in mutation:
                span.outputs = dict(mutation["outputs"])
                span.data["output"] = span.outputs
            if "data" in mutation:
                span.data.update(mutation["data"])
            if span.type == "tool":
                span.data["success"] = span.status == "ok"
            ensure_typed_data(span)

    if cascade and not any(
        s.type in {"tool", "retrieval", "policy"} and s.status in {"error", "timeout"} for s in clone.spans
    ):
        for span in clone.spans:
            if span.type == "agent" and span.status == "error":
                if require_capability and span.span_id not in patch.capability.allowed_span_ids:
                    raise SecurityDivergence(
                        f"heal cascade cleared agent outside capability: {span.span_id}",
                        details={"span_id": span.span_id},
                    )
                span.status = "ok"
                span.error = None

    clone.status = (
        "failed"
        if any(s.status in {"error", "timeout"} for s in clone.spans)
        else "completed"
    )
    from sage.schema import new_id

    clone.bundle_id = new_id("bundle")
    for span in clone.spans:
        span.trace_id = clone.bundle_id
    clone.metadata = {
        **clone.metadata,
        "healed_from_bundle_id": bundle.bundle_id,
        "healed_span_id": span_id,
        "heal_capability": patch.capability.to_dict(),
        "heal_patch": patch.to_dict(),
    }
    if clone.status == "failed":
        clone.metadata["secondary_failure"] = True
        for span in clone.spans:
            if span.status == "error":
                clone.root_cause_hint = span.span_id
                span.is_suspected_root_cause = True
                break
    else:
        clone.root_cause_hint = None
    return finalize_bundle(clone, redact=False, status=clone.status)


def strict_replay_handler(cassette: ReplayCassette) -> ReplayHandler:
    def _handler(span: SageSpan) -> dict[str, Any] | None:
        match = cassette.lookup(span)
        if match is None:
            return None
        return dict(match.outputs)

    return _handler
