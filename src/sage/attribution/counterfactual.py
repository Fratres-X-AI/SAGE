from __future__ import annotations

import copy
from dataclasses import dataclass

from sage.attribution.heuristics import AttributionCandidate
from sage.schema import IncidentBundle, SageSpan


def _failure_score(bundle: IncidentBundle) -> float:
    score = 0.0
    for span in bundle.spans:
        if span.status in {"error", "timeout", "cancelled"}:
            score += 1.0
        if span.error:
            score += 0.5
        blob = f"{span.outputs}{span.data}{span.error.message if span.error else ''}".lower()
        if "schema" in blob and "required" in blob:
            score += 0.75
        if "denied" in blob or "unauthorized" in blob:
            score += 0.75
    return score


def _heal_span(span: SageSpan) -> SageSpan:
    healed = copy.deepcopy(span)
    healed.status = "ok"
    healed.error = None
    outputs = dict(healed.outputs)
    if healed.type == "retrieval":
        docs = outputs.get("documents") or healed.data.get("documents")
        if isinstance(docs, list):
            fixed_docs = []
            for doc in docs:
                if isinstance(doc, dict):
                    item = dict(doc)
                    if "schema_version" in item:
                        item["schema_version"] = "v2"
                    item.pop("stale", None)
                    fixed_docs.append(item)
                else:
                    fixed_docs.append(doc)
            outputs["documents"] = fixed_docs
            healed.data["documents"] = fixed_docs
        outputs["fresh"] = True
    elif healed.type == "llm":
        response = outputs.get("response")
        if isinstance(response, dict):
            fixed = dict(response)
            if "schema" in fixed:
                fixed["schema"] = "v2"
            if "args" in fixed and isinstance(fixed["args"], dict):
                args = dict(fixed["args"])
                if "schema" in args:
                    args["schema"] = "v2"
                fixed["args"] = args
            outputs["response"] = fixed
        outputs["grounded"] = True
    elif healed.type == "tool":
        outputs = {"result": "ok", "repaired": True}
        healed.data["success"] = True
    elif healed.type == "policy":
        outputs = {"decision": "allow"}
        healed.data["decision"] = "allow"
    healed.outputs = outputs
    healed.data["output"] = outputs
    return healed


def _propagate_heal(bundle: IncidentBundle, intervene_index: int) -> IncidentBundle:
    """Apply a heal at intervene_index and cascade simple consistency fixes."""
    raw = copy.deepcopy(bundle.to_dict())
    raw["audit"] = {"chain": [], "bundle_hash": ""}
    clone = IncidentBundle.from_dict(raw)
    clone.spans[intervene_index] = _heal_span(clone.spans[intervene_index])

    healed = clone.spans[intervene_index]
    healed_type = healed.type
    if healed_type in {"retrieval", "llm"}:
        # Cascade by symptom match, not list index — audit sort order can place
        # tools before the retrieval span that caused them.
        for idx, later in enumerate(list(clone.spans)):
            if later.span_id == healed.span_id:
                continue
            err = later.error.message if later.error else ""
            blob = f"{later.inputs}{later.outputs}{err}".lower()
            if later.type in {"tool", "llm"} and ("schema" in blob or later.status in {"error", "timeout"}):
                clone.spans[idx] = _heal_span(later)
    # Clear cascading agent failures once downstream actionable errors are gone.
    if not any(s.type in {"tool", "retrieval", "policy"} and s.status in {"error", "timeout"} for s in clone.spans):
        for span in clone.spans:
            if span.type == "agent" and span.status == "error":
                span.status = "ok"
                span.error = None
    return clone


@dataclass
class CounterfactualResult:
    baseline_failure: float
    ranked: list[AttributionCandidate]


def counterfactual_attribute(bundle: IncidentBundle, *, top_k: int = 5) -> CounterfactualResult:
    """Rank spans by how much healing them reduces failure score."""
    baseline = _failure_score(bundle)
    ranked: list[AttributionCandidate] = []
    for index, span in enumerate(bundle.spans):
        intervened = _propagate_heal(bundle, index)
        after = _failure_score(intervened)
        delta = max(baseline - after, 0.0)
        bonus = 0.0
        if span.status in {"error", "timeout"}:
            bonus += 0.01
        if span.is_suspected_root_cause:
            bonus += 0.2
        blob = f"{span.inputs}{span.outputs}{span.data}".lower()
        if span.type == "retrieval" and ("stale" in blob or "schema_version" in blob):
            bonus += 0.15
        # Prefer earlier causal spans on ties.
        bonus += 0.001 * (len(bundle.spans) - index)
        ranked.append(
            AttributionCandidate(
                span_id=span.span_id,
                span_name=span.name,
                kind=span.kind,
                score=delta + bonus,
                reason="counterfactual_heal_delta",
            )
        )
    ranked.sort(key=lambda c: c.score, reverse=True)
    return CounterfactualResult(baseline_failure=baseline, ranked=ranked[:top_k])
