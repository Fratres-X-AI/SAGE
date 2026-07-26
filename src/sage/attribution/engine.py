from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from sage.attribution.counterfactual import counterfactual_attribute
from sage.attribution.heuristics import AttributionCandidate, heuristic_attribute
from sage.attribution.model import NeuralAttribution
from sage.schema import IncidentBundle


def attribute_incident(
    bundle: IncidentBundle,
    *,
    method: str = "auto",
    model_path: str | Path | None = None,
    top_k: int = 5,
) -> list[AttributionCandidate]:
    """Unified attribution API.

    Methods:
      - heuristic: fast rules
      - counterfactual: intervene-and-heal ranking
      - neural: trained span-cause encoder
      - ensemble: neural + counterfactual fusion
      - auto: ensemble if model exists else counterfactual
    """
    path = Path(model_path) if model_path else Path("artifacts/span_cause.pt")
    selected = method
    if selected == "auto":
        selected = "ensemble" if path.exists() else "counterfactual"

    if selected == "heuristic":
        return heuristic_attribute(bundle, top_k=top_k)
    if selected == "counterfactual":
        return counterfactual_attribute(bundle, top_k=top_k).ranked
    if selected == "neural":
        return NeuralAttribution(path).attribute(bundle, top_k=top_k)
    if selected == "ensemble":
        neural = NeuralAttribution(path).attribute(bundle, top_k=max(top_k, 8))
        cf = counterfactual_attribute(bundle, top_k=max(top_k, 8)).ranked
        neural_map = {c.span_id: c.score for c in neural}
        cf_map = {c.span_id: c.score for c in cf}
        fused = [
            AttributionCandidate(
                span_id=span.id,
                span_name=span.name,
                kind=span.kind,
                score=0.65 * neural_map.get(span.id, 0.0) + 0.35 * cf_map.get(span.id, 0.0),
                reason="ensemble_neural_cf",
            )
            for span in bundle.spans
        ]
        fused.sort(key=lambda c: c.score, reverse=True)
        return fused[:top_k]
    raise ValueError(f"unknown attribution method: {method}")


def attribution_report(bundle: IncidentBundle, **kwargs) -> dict:
    ranked = attribute_incident(bundle, **kwargs)
    return {
        "run_id": bundle.run_id,
        "title": bundle.title,
        "ranked": [asdict(c) for c in ranked],
        "top_span_id": ranked[0].span_id if ranked else None,
    }
