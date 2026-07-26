from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from sage.attribution.features import FEATURE_DIM, bundle_feature_matrix
from sage.attribution.heuristics import AttributionCandidate
from sage.schema import IncidentBundle

try:
    import torch
    from torch import nn
except ImportError:  # pragma: no cover
    torch = None  # type: ignore[assignment]
    nn = None  # type: ignore[assignment]


def _require_torch() -> None:
    if torch is None:
        raise ImportError("PyTorch is required for neural attribution. Install with: pip install -e '.[train]'")


class SpanCauseEncoder(nn.Module if nn is not None else object):  # type: ignore[misc]
    """Sequence encoder that scores each span as a potential root cause."""

    def __init__(self, feature_dim: int = FEATURE_DIM, hidden: int = 128, max_spans: int = 32) -> None:
        _require_torch()
        super().__init__()
        self.max_spans = max_spans
        self.proj = nn.Sequential(
            nn.Linear(feature_dim, hidden),
            nn.GELU(),
            nn.LayerNorm(hidden),
        )
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=hidden,
            nhead=4,
            dim_feedforward=hidden * 2,
            batch_first=True,
            activation="gelu",
            dropout=0.1,
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=3)
        self.head = nn.Linear(hidden, 1)

    def forward(self, x: Any, mask: Any) -> Any:
        h = self.proj(x)
        h = self.encoder(h, src_key_padding_mask=mask)
        logits = self.head(h).squeeze(-1)
        return logits.masked_fill(mask, -1e9)


@dataclass
class NeuralAttribution:
    model_path: Path
    max_spans: int = 32
    device: str | None = None

    def __post_init__(self) -> None:
        _require_torch()
        self.device = self.device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.model = SpanCauseEncoder(max_spans=self.max_spans)
        try:
            state = torch.load(self.model_path, map_location=self.device, weights_only=True)
        except Exception:
            state = torch.load(self.model_path, map_location=self.device, weights_only=False)
        self.model.load_state_dict(state["model"])
        self.model.to(self.device)
        self.model.eval()

    def attribute(self, bundle: IncidentBundle, *, top_k: int = 5) -> list[AttributionCandidate]:
        matrix, ids = bundle_feature_matrix(bundle, max_spans=self.max_spans)
        length = min(len(bundle.spans), self.max_spans)
        if length == 0:
            return []
        x = torch.tensor(matrix[None, ...], dtype=torch.float32, device=self.device)
        mask = torch.zeros((1, self.max_spans), dtype=torch.bool, device=self.device)
        if length < self.max_spans:
            mask[:, length:] = True
        with torch.inference_mode():
            logits = self.model(x, mask)[0, :length].detach().cpu().numpy()
        probs = _softmax(logits)
        order = np.argsort(-probs)
        out: list[AttributionCandidate] = []
        for idx in order[:top_k]:
            span = bundle.spans[int(idx)]
            out.append(
                AttributionCandidate(
                    span_id=ids[int(idx)],
                    span_name=span.name,
                    kind=span.kind,
                    score=float(probs[int(idx)]),
                    reason="neural_span_cause",
                )
            )
        return out


def _softmax(values: np.ndarray) -> np.ndarray:
    shifted = values - values.max()
    exp = np.exp(shifted)
    return exp / max(exp.sum(), 1e-12)
