from __future__ import annotations

from dataclasses import dataclass

from sage.schema import IncidentBundle, SageSpan


@dataclass
class AttributionCandidate:
    span_id: str
    span_name: str
    kind: str
    score: float
    reason: str


def _is_failure(span: SageSpan) -> bool:
    return span.status in {"error", "timeout", "cancelled"} or bool(span.error)


def _score_error_span(span: SageSpan, index: int, total: int) -> float:
    score = 0.0
    if _is_failure(span):
        score += 0.55
    if span.error:
        score += 0.15
    if span.type in {"tool", "retrieval", "llm", "policy"} or span.kind in {
        "TOOL",
        "RETRIEVER",
        "LLM",
        "POLICY",
    }:
        score += 0.1
    score += 0.2 * (1.0 - index / max(total - 1, 1))
    return score


def heuristic_attribute(bundle: IncidentBundle, *, top_k: int = 5) -> list[AttributionCandidate]:
    """Fast, training-free root-cause ranking over spans."""
    spans = bundle.spans
    if not spans:
        return []

    candidates: list[AttributionCandidate] = []
    for index, span in enumerate(spans):
        score = _score_error_span(span, index, len(spans))
        reason = "status_or_error_signal"
        err_text = span.error.message if span.error else ""
        blob = f"{span.inputs}{span.outputs}{span.attributes}{span.data}{err_text}".lower()
        if "schema" in blob and span.type in {"retrieval", "tool", "llm"}:
            score += 0.25
            reason = "schema_drift_signal"
        if "stale" in blob or "outdated" in blob:
            score += 0.2
            reason = "stale_context_signal"
        if span.type == "retrieval" and any(_is_failure(later) for later in spans[index + 1 :]):
            score += 0.15
            reason = "retriever_precedes_failure"
        decision = span.data.get("decision") or span.outputs.get("decision")
        if span.type == "policy" and decision == "deny":
            score += 0.3
            reason = "policy_denial"
        if span.is_suspected_root_cause:
            score += 0.5
            reason = "annotated_root_cause"

        if not _is_failure(span) and span.type not in {"retrieval", "llm", "tool", "policy"}:
            score *= 0.4

        candidates.append(
            AttributionCandidate(
                span_id=span.span_id,
                span_name=span.name,
                kind=span.kind,
                score=score,
                reason=reason,
            )
        )

    candidates.sort(key=lambda c: c.score, reverse=True)
    return candidates[:top_k]


def heuristic_top_span_id(bundle: IncidentBundle) -> str | None:
    ranked = heuristic_attribute(bundle, top_k=1)
    return ranked[0].span_id if ranked else None
