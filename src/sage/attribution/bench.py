from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from sage.attribution.counterfactual import counterfactual_attribute
from sage.attribution.heuristics import AttributionCandidate, heuristic_attribute
from sage.attribution.model import NeuralAttribution
from sage.synth.failures import LabeledIncident, generate_corpus, load_corpus


@dataclass
class MethodScore:
    name: str
    accuracy_at_1: float
    accuracy_at_3: float
    n: int


def _score_method(name: str, items: list[LabeledIncident], predict_top) -> MethodScore:
    hit1 = 0
    hit3 = 0
    for item in items:
        ranked = predict_top(item)
        ids = [c.span_id for c in ranked]
        if ids and ids[0] == item.root_cause_span_id:
            hit1 += 1
        if item.root_cause_span_id in ids[:3]:
            hit3 += 1
    n = max(len(items), 1)
    return MethodScore(name=name, accuracy_at_1=hit1 / n, accuracy_at_3=hit3 / n, n=len(items))


def run_benchmark(
    *,
    n: int = 1000,
    seed: int = 99,
    model_path: str | Path | None = None,
    corpus_dir: str | Path | None = None,
    out_path: str | Path | None = None,
) -> dict:
    items = load_corpus(corpus_dir) if corpus_dir else generate_corpus(n, seed=seed, hard=True)

    results = [
        _score_method("heuristic", items, lambda item: heuristic_attribute(item.bundle, top_k=3)),
        _score_method(
            "counterfactual",
            items,
            lambda item: counterfactual_attribute(item.bundle, top_k=3).ranked,
        ),
    ]

    if model_path and Path(model_path).exists():
        neural = NeuralAttribution(Path(model_path))
        results.append(
            _score_method("neural", items, lambda item: neural.attribute(item.bundle, top_k=3))
        )

        def ensemble_top(item: LabeledIncident) -> list[AttributionCandidate]:
            neural_ranks = {c.span_id: c.score for c in neural.attribute(item.bundle, top_k=8)}
            cf_ranks = {
                c.span_id: c.score for c in counterfactual_attribute(item.bundle, top_k=8).ranked
            }
            candidates = [
                AttributionCandidate(
                    span_id=span.id,
                    span_name=span.name,
                    kind=span.kind,
                    score=0.65 * neural_ranks.get(span.id, 0.0) + 0.35 * cf_ranks.get(span.id, 0.0),
                    reason="ensemble_neural_cf",
                )
                for span in item.bundle.spans
            ]
            candidates.sort(key=lambda c: c.score, reverse=True)
            return candidates[:3]

        results.append(_score_method("ensemble", items, ensemble_top))

    payload = {
        "n": len(items),
        "methods": [
            {
                "name": r.name,
                "accuracy@1": r.accuracy_at_1,
                "accuracy@3": r.accuracy_at_3,
            }
            for r in results
        ],
    }
    if out_path:
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload
