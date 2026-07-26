from __future__ import annotations

import hashlib
import json
from typing import Any

from sage.schema import IncidentBundle, SageSpan

try:
    import numpy as np
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "numpy is required for attribution features. Install with: pip install -e '.[attr]'"
    ) from exc

KIND_VOCAB = [
    "AGENT",
    "CHAIN",
    "EMBEDDING",
    "EVALUATOR",
    "GUARDRAIL",
    "HUMAN",
    "LLM",
    "POLICY",
    "PROMPT",
    "RERANKER",
    "RETRIEVER",
    "TOOL",
    "HANDOFF",
    "CUSTOM",
]
STATUS_VOCAB = ["ok", "error", "cancelled", "timeout", "OK", "ERROR", "UNSET", "BLOCKED"]
FEATURE_DIM = len(KIND_VOCAB) + len(STATUS_VOCAB) + 12


def _blob(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def _has_keyword(text: str, keywords: tuple[str, ...]) -> float:
    lowered = text.lower()
    return float(any(k in lowered for k in keywords))


def span_feature_vector(span: SageSpan, index: int, total: int) -> np.ndarray:
    vec = np.zeros(FEATURE_DIM, dtype=np.float32)
    offset = 0
    if span.kind in KIND_VOCAB:
        vec[offset + KIND_VOCAB.index(span.kind)] = 1.0
    offset += len(KIND_VOCAB)
    if span.status in STATUS_VOCAB:
        vec[offset + STATUS_VOCAB.index(span.status)] = 1.0
    offset += len(STATUS_VOCAB)

    blob = _blob({"i": span.inputs, "o": span.outputs, "a": span.attributes, "e": span.error})
    extras = [
        index / max(total - 1, 1),
        float(span.error is not None),
        float(span.status in {"error", "timeout", "cancelled", "ERROR", "BLOCKED"}),
        _has_keyword(blob, ("schema", "version", "drift")),
        _has_keyword(blob, ("stale", "outdated", "expired")),
        _has_keyword(blob, ("timeout", "latency", "slow")),
        _has_keyword(blob, ("permission", "denied", "unauthorized", "policy")),
        _has_keyword(blob, ("hallucin", "fabricat", "ungrounded")),
        float("confidence" in span.attributes),
        float(span.attributes.get("confidence", 0.5) if isinstance(span.attributes.get("confidence"), (int, float)) else 0.5),
        float(bool(span.parent_id)),
        min(len(blob) / 2000.0, 1.0),
    ]
    vec[offset : offset + len(extras)] = extras
    return vec


def bundle_feature_matrix(bundle: IncidentBundle, *, max_spans: int = 32) -> tuple[np.ndarray, list[str]]:
    spans = bundle.spans[:max_spans]
    matrix = np.zeros((max_spans, FEATURE_DIM), dtype=np.float32)
    ids: list[str] = []
    for i, span in enumerate(spans):
        matrix[i] = span_feature_vector(span, i, len(spans))
        ids.append(span.id)
    return matrix, ids


def label_index_for_span_id(bundle: IncidentBundle, span_id: str, *, max_spans: int = 32) -> int:
    for i, span in enumerate(bundle.spans[:max_spans]):
        if span.id == span_id:
            return i
    raise ValueError(f"span_id {span_id} not found in bundle")


def content_fingerprint(span: SageSpan) -> str:
    payload = {"kind": span.kind, "name": span.name, "inputs": span.inputs, "outputs": span.outputs}
    return hashlib.sha256(_blob(payload).encode("utf-8")).hexdigest()[:16]
