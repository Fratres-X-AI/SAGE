from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from sage.schema import IncidentBundle, SageSpan


@dataclass
class FieldDiff:
    path: str
    expected: Any
    actual: Any


@dataclass
class SpanDivergence:
    span_id: str
    span_name: str
    span_type: str
    reason: str
    field_diffs: list[FieldDiff] = field(default_factory=list)
    cascading: bool = False


@dataclass
class DivergenceReport:
    ok: bool
    first_divergence_span_id: str | None
    divergent_span_count: int
    matched_span_count: int
    divergences: list[SpanDivergence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "first_divergence_span_id": self.first_divergence_span_id,
            "divergent_span_count": self.divergent_span_count,
            "matched_span_count": self.matched_span_count,
            "divergences": [
                {
                    "span_id": d.span_id,
                    "span_name": d.span_name,
                    "span_type": d.span_type,
                    "reason": d.reason,
                    "cascading": d.cascading,
                    "field_diffs": [asdict(fd) for fd in d.field_diffs],
                }
                for d in self.divergences
            ],
        }


def deep_diff(expected: Any, actual: Any, *, path: str = "") -> list[FieldDiff]:
    diffs: list[FieldDiff] = []
    if type(expected) is not type(actual) and not (
        isinstance(expected, (int, float)) and isinstance(actual, (int, float))
    ):
        diffs.append(FieldDiff(path=path or "$", expected=expected, actual=actual))
        return diffs
    if isinstance(expected, dict):
        keys = sorted(set(expected) | set(actual))
        for key in keys:
            child = f"{path}.{key}" if path else str(key)
            if key not in expected:
                diffs.append(FieldDiff(path=child, expected=None, actual=actual.get(key)))
            elif key not in actual:
                diffs.append(FieldDiff(path=child, expected=expected.get(key), actual=None))
            else:
                diffs.extend(deep_diff(expected[key], actual[key], path=child))
        return diffs
    if isinstance(expected, list):
        if len(expected) != len(actual):
            diffs.append(FieldDiff(path=path or "$", expected=expected, actual=actual))
            return diffs
        for index, (left, right) in enumerate(zip(expected, actual)):
            child = f"{path}.{index}" if path else str(index)
            diffs.extend(deep_diff(left, right, path=child))
        return diffs
    if expected != actual:
        diffs.append(FieldDiff(path=path or "$", expected=expected, actual=actual))
    return diffs


def _span_core(span: SageSpan) -> dict[str, Any]:
    return {
        "type": span.type,
        "name": span.name,
        "status": span.status,
        "error": span.error.to_dict() if span.error else None,
        "inputs": span.inputs,
        "outputs": span.outputs,
        "data": span.data,
        "agent_id": span.agent_id,
    }


def diff_bundles(expected: IncidentBundle, actual: IncidentBundle) -> DivergenceReport:
    """Structured field-level divergence between two bundles."""
    exp_map = {s.span_id: s for s in expected.spans}
    act_map = {s.span_id: s for s in actual.spans}
    # Align by position for replayable types when ids differ
    exp_replayable = [s for s in expected.spans if s.type in {"llm", "tool", "retrieval"}]
    act_replayable = [s for s in actual.spans if s.type in {"llm", "tool", "retrieval"}]

    divergences: list[SpanDivergence] = []
    matched = 0
    first_id: str | None = None
    seen_divergence = False

    # Prefer id alignment; fall back to positional replayable alignment
    if set(exp_map) & set(act_map):
        pairs: list[tuple[SageSpan | None, SageSpan | None]] = []
        for span_id in sorted(set(exp_map) | set(act_map)):
            pairs.append((exp_map.get(span_id), act_map.get(span_id)))
    else:
        length = max(len(exp_replayable), len(act_replayable))
        pairs = []
        for i in range(length):
            left = exp_replayable[i] if i < len(exp_replayable) else None
            right = act_replayable[i] if i < len(act_replayable) else None
            pairs.append((left, right))

    for left, right in pairs:
        if left is None and right is not None:
            div = SpanDivergence(
                span_id=right.span_id,
                span_name=right.name,
                span_type=right.type,
                reason="unexpected_extra_span",
                field_diffs=[FieldDiff(path="$", expected=None, actual=_span_core(right))],
                cascading=seen_divergence,
            )
            divergences.append(div)
            first_id = first_id or right.span_id
            seen_divergence = True
            continue
        if right is None and left is not None:
            div = SpanDivergence(
                span_id=left.span_id,
                span_name=left.name,
                span_type=left.type,
                reason="missing_span",
                field_diffs=[FieldDiff(path="$", expected=_span_core(left), actual=None)],
                cascading=seen_divergence,
            )
            divergences.append(div)
            first_id = first_id or left.span_id
            seen_divergence = True
            continue
        assert left is not None and right is not None
        field_diffs = deep_diff(_span_core(left), _span_core(right))
        if field_diffs:
            reason = "field_mismatch"
            if left.status != right.status:
                reason = "status_changed"
            elif left.outputs != right.outputs or left.data.get("output") != right.data.get("output"):
                reason = "output_changed"
            div = SpanDivergence(
                span_id=left.span_id,
                span_name=left.name,
                span_type=left.type,
                reason=reason,
                field_diffs=field_diffs,
                cascading=seen_divergence,
            )
            divergences.append(div)
            first_id = first_id or left.span_id
            seen_divergence = True
        else:
            matched += 1

    return DivergenceReport(
        ok=not divergences,
        first_divergence_span_id=first_id,
        divergent_span_count=len(divergences),
        matched_span_count=matched,
        divergences=divergences,
    )
