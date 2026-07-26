from __future__ import annotations

import random

from sage.attribution.counterfactual import counterfactual_attribute
from sage.attribution.engine import attribute_incident
from sage.attribution.heuristics import heuristic_attribute
from sage.synth.failures import make_policy_block, make_stale_retrieval_schema


def test_heuristic_finds_stale_retrieval_root_cause():
    item = make_stale_retrieval_schema(random.Random(0))
    ranked = heuristic_attribute(item.bundle, top_k=3)
    assert ranked
    assert item.root_cause_span_id in {c.span_id for c in ranked}


def test_counterfactual_prefers_retriever_for_schema_drift():
    item = make_stale_retrieval_schema(random.Random(1))
    ranked = counterfactual_attribute(item.bundle, top_k=5).ranked
    root = item.bundle.root_cause_hint or item.root_cause_span_id
    assert root in {c.span_id for c in ranked}
    # Annotated / stale retrieval should outrank pure symptom tool spans.
    by_id = {c.span_id: c for c in ranked}
    tool = next(s for s in item.bundle.spans if s.type == "tool")
    if root in by_id and tool.span_id in by_id:
        assert by_id[root].score >= by_id[tool.span_id].score


def test_attribute_auto_uses_counterfactual_without_model():
    item = make_policy_block(random.Random(2))
    ranked = attribute_incident(item.bundle, method="counterfactual", top_k=1)
    assert ranked[0].span_id == item.root_cause_span_id
