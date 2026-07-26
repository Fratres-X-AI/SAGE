from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from sage.attribution.features import FEATURE_DIM, bundle_feature_matrix, label_index_for_span_id
from sage.attribution.model import SpanCauseEncoder, _require_torch
from sage.synth.failures import LabeledIncident, generate_corpus, load_corpus

try:
    import torch
    from torch import nn
    from torch.utils.data import DataLoader, Dataset
except ImportError:  # pragma: no cover
    torch = None  # type: ignore[assignment]
    nn = None  # type: ignore[assignment]
    DataLoader = object  # type: ignore[misc, assignment]
    Dataset = object  # type: ignore[misc, assignment]


class IncidentCauseDataset(Dataset):  # type: ignore[misc]
    def __init__(self, items: list[LabeledIncident], *, max_spans: int = 32) -> None:
        self.items = items
        self.max_spans = max_spans

    def __len__(self) -> int:
        return len(self.items)

    def __getitem__(self, index: int) -> dict[str, Any]:
        item = self.items[index]
        matrix, _ = bundle_feature_matrix(item.bundle, max_spans=self.max_spans)
        length = min(len(item.bundle.spans), self.max_spans)
        label = label_index_for_span_id(item.bundle, item.root_cause_span_id, max_spans=self.max_spans)
        mask = np.zeros(self.max_spans, dtype=np.bool_)
        if length < self.max_spans:
            mask[length:] = True
        return {
            "x": torch.tensor(matrix, dtype=torch.float32),
            "mask": torch.tensor(mask, dtype=torch.bool),
            "label": torch.tensor(label, dtype=torch.long),
            "length": length,
        }


@dataclass
class TrainConfig:
    n_train: int = 4000
    n_val: int = 800
    epochs: int = 12
    batch_size: int = 64
    lr: float = 2e-3
    max_spans: int = 32
    seed: int = 7
    hidden: int = 128
    out_dir: Path = Path("artifacts")


def _accuracy(logits: Any, labels: Any, masks: Any) -> float:
    pred = logits.argmax(dim=-1)
    correct = (pred == labels).float()
    return float(correct.mean().item())


def train_attribution_model(config: TrainConfig | None = None) -> dict[str, Any]:
    _require_torch()
    assert torch is not None
    cfg = config or TrainConfig()
    cfg.out_dir.mkdir(parents=True, exist_ok=True)

    device = "cuda" if torch.cuda.is_available() else "cpu"
    torch.manual_seed(cfg.seed)
    np.random.seed(cfg.seed)

    # Keep training corpora in-memory for speed; optional disk export is via `sage synth`.
    train_items = generate_corpus(cfg.n_train, seed=cfg.seed, out_dir=None, hard=True)
    val_items = generate_corpus(cfg.n_val, seed=cfg.seed + 1, out_dir=None, hard=True)

    train_loader = DataLoader(IncidentCauseDataset(train_items, max_spans=cfg.max_spans), batch_size=cfg.batch_size, shuffle=True)
    val_loader = DataLoader(IncidentCauseDataset(val_items, max_spans=cfg.max_spans), batch_size=cfg.batch_size)

    model = SpanCauseEncoder(feature_dim=FEATURE_DIM, hidden=cfg.hidden, max_spans=cfg.max_spans).to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=cfg.lr)
    loss_fn = nn.CrossEntropyLoss()

    history: list[dict[str, float]] = []
    best_val = -1.0
    best_path = cfg.out_dir / "span_cause.pt"

    for epoch in range(1, cfg.epochs + 1):
        model.train()
        train_losses: list[float] = []
        train_accs: list[float] = []
        for batch in train_loader:
            x = batch["x"].to(device)
            mask = batch["mask"].to(device)
            labels = batch["label"].to(device)
            opt.zero_grad(set_to_none=True)
            logits = model(x, mask)
            loss = loss_fn(logits, labels)
            loss.backward()
            opt.step()
            train_losses.append(float(loss.item()))
            train_accs.append(_accuracy(logits, labels, mask))

        model.eval()
        val_accs: list[float] = []
        with torch.inference_mode():
            for batch in val_loader:
                x = batch["x"].to(device)
                mask = batch["mask"].to(device)
                labels = batch["label"].to(device)
                logits = model(x, mask)
                val_accs.append(_accuracy(logits, labels, mask))

        row = {
            "epoch": float(epoch),
            "train_loss": float(np.mean(train_losses)),
            "train_acc": float(np.mean(train_accs)),
            "val_acc": float(np.mean(val_accs)),
        }
        history.append(row)
        if row["val_acc"] >= best_val:
            best_val = row["val_acc"]
            torch.save(
                {
                    "model": model.state_dict(),
                    "feature_dim": FEATURE_DIM,
                    "max_spans": cfg.max_spans,
                    "hidden": cfg.hidden,
                },
                best_path,
            )

    metrics = {
        "device": device,
        "best_val_acc": best_val,
        "model_path": str(best_path),
        "history": history,
        "n_train": cfg.n_train,
        "n_val": cfg.n_val,
        "epochs": cfg.epochs,
    }
    (cfg.out_dir / "train_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


def train_from_corpus(train_dir: Path, val_dir: Path, out_dir: Path, *, epochs: int = 12) -> dict[str, Any]:
    _require_torch()
    assert torch is not None
    cfg = TrainConfig(epochs=epochs, out_dir=out_dir, n_train=0, n_val=0)
    train_items = load_corpus(train_dir)
    val_items = load_corpus(val_dir)
    # Monkeypatch generation by calling internal loop with loaded items
    device = "cuda" if torch.cuda.is_available() else "cpu"
    out_dir.mkdir(parents=True, exist_ok=True)
    train_loader = DataLoader(IncidentCauseDataset(train_items), batch_size=cfg.batch_size, shuffle=True)
    val_loader = DataLoader(IncidentCauseDataset(val_items), batch_size=cfg.batch_size)
    model = SpanCauseEncoder().to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=cfg.lr)
    loss_fn = nn.CrossEntropyLoss()
    best_val = -1.0
    best_path = out_dir / "span_cause.pt"
    history = []
    for epoch in range(1, epochs + 1):
        model.train()
        for batch in train_loader:
            x = batch["x"].to(device)
            mask = batch["mask"].to(device)
            labels = batch["label"].to(device)
            opt.zero_grad(set_to_none=True)
            logits = model(x, mask)
            loss_fn(logits, labels).backward()
            opt.step()
        model.eval()
        accs = []
        with torch.inference_mode():
            for batch in val_loader:
                logits = model(batch["x"].to(device), batch["mask"].to(device))
                accs.append(_accuracy(logits, batch["label"].to(device), batch["mask"].to(device)))
        val_acc = float(np.mean(accs)) if accs else 0.0
        history.append({"epoch": epoch, "val_acc": val_acc})
        if val_acc >= best_val:
            best_val = val_acc
            torch.save({"model": model.state_dict(), "feature_dim": FEATURE_DIM, "max_spans": 32}, best_path)
    metrics = {"device": device, "best_val_acc": best_val, "model_path": str(best_path), "history": history}
    (out_dir / "train_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics
