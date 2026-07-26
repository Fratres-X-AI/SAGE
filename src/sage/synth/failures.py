from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from sage.audit import finalize_bundle
from sage.schema import IncidentBundle, SageSpan, SpanError, ensure_typed_data, new_id

FailureMode = Literal[
    "stale_retrieval_schema",
    "tool_permission_denied",
    "llm_ungrounded_args",
    "policy_block",
    "retriever_timeout_cascade",
]


@dataclass
class LabeledIncident:
    bundle: IncidentBundle
    root_cause_span_id: str
    failure_mode: FailureMode

    def to_dict(self) -> dict:
        return {
            "root_cause_span_id": self.root_cause_span_id,
            "failure_mode": self.failure_mode,
            "bundle": self.bundle.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "LabeledIncident":
        return cls(
            bundle=IncidentBundle.from_dict(data["bundle"]),
            root_cause_span_id=data["root_cause_span_id"],
            failure_mode=data["failure_mode"],
        )


def _agent_root(goal: str) -> SageSpan:
    span = SageSpan.from_kind("AGENT", "orchestrator", inputs={"goal": goal}, agent_id="orchestrator")
    span.finish(status="ok")
    ensure_typed_data(span)
    return span


def _finalize(spans: list[SageSpan], root_id: str, mode: FailureMode, title: str) -> LabeledIncident:
    bundle = IncidentBundle(
        title=title,
        metadata={"failure_mode": mode},
        root_cause_hint=root_id,
        status="failed",
    )
    for span in spans:
        span.trace_id = bundle.bundle_id
        if not span.end_time:
            span.finish(status=span.status)
        ensure_typed_data(span)
        if span.span_id == root_id:
            span.is_suspected_root_cause = True
            span.failure_context = mode
        bundle.add_span(span)
    finalized = finalize_bundle(bundle, redact=True, status="failed")
    # Prefer the hint on the finalized artifact (ids are preserved through redact/hash).
    finalized_root = finalized.root_cause_hint or root_id
    if isinstance(finalized_root, list):
        finalized_root = finalized_root[0]
    return LabeledIncident(bundle=finalized, root_cause_span_id=str(finalized_root), failure_mode=mode)


def make_stale_retrieval_schema(rng: random.Random) -> LabeledIncident:
    agent = _agent_root("update customer tier")
    retrieval = SageSpan.from_kind(
        "RETRIEVER",
        "fetch_profile",
        parent_id=agent.id,
        agent_id="researcher",
        inputs={"customer_id": f"cust_{rng.randint(1, 999)}", "query": "profile"},
        outputs={"documents": [{"id": "d1", "tier": "gold", "schema_version": "v1", "stale": True}]},
        attributes={"confidence": 0.9},
    )
    retrieval.finish(status="ok")
    llm = SageSpan.from_kind(
        "LLM",
        "plan_update",
        parent_id=agent.id,
        agent_id="planner",
        inputs={"prompt": "choose tool args"},
        outputs={"response": {"tool": "update_tier", "args": {"schema": "v1"}}},
        attributes={"model": "synth-llm"},
    )
    llm.finish(status="ok")
    tool = SageSpan.from_kind(
        "TOOL",
        "update_tier",
        parent_id=agent.id,
        agent_id="executor",
        inputs={"schema": "v1"},
        outputs={"error": "schema v2 required; v1 rejected"},
    )
    tool.finish(status="error", error="schema drift")
    agent.status = "error"
    agent.error = SpanError(type="Error", message="downstream tool failure")
    return _finalize([agent, retrieval, llm, tool], retrieval.id, "stale_retrieval_schema", "stale_retrieval_schema")


def make_tool_permission_denied(rng: random.Random) -> LabeledIncident:
    agent = _agent_root("refund order")
    llm = SageSpan.from_kind(
        "LLM",
        "choose_action",
        parent_id=agent.id,
        inputs={"prompt": "refund"},
        outputs={"response": {"tool": "issue_refund"}},
        attributes={"model": "synth-llm"},
    )
    llm.finish(status="ok")
    tool = SageSpan.from_kind(
        "TOOL",
        "issue_refund",
        parent_id=agent.id,
        inputs={"order_id": f"ord_{rng.randint(100, 999)}", "amount": rng.randint(10, 400)},
        outputs={"error": "unauthorized: missing refund:write permission"},
    )
    tool.finish(status="error", error="permission denied")
    agent.status = "error"
    agent.error = SpanError(type="Error", message="tool unauthorized")
    return _finalize([agent, llm, tool], tool.id, "tool_permission_denied", "tool_permission_denied")


def make_llm_ungrounded_args(rng: random.Random) -> LabeledIncident:
    agent = _agent_root("book meeting")
    retrieval = SageSpan.from_kind(
        "RETRIEVER",
        "calendar_slots",
        parent_id=agent.id,
        inputs={"query": "tomorrow"},
        outputs={"documents": [{"id": "s1", "slot": "10:00"}, {"id": "s2", "slot": "14:00"}]},
    )
    retrieval.finish(status="ok")
    llm = SageSpan.from_kind(
        "LLM",
        "pick_slot",
        parent_id=agent.id,
        inputs={"prompt": "book available slot"},
        outputs={"response": {"tool": "book", "args": {"slot": "19:00"}}, "hallucinated": True},
        attributes={"confidence": 0.31, "model": "synth-llm"},
    )
    llm.finish(status="error", error="ungrounded slot")
    tool = SageSpan.from_kind(
        "TOOL",
        "book",
        parent_id=agent.id,
        inputs={"slot": "19:00"},
        outputs={"error": "slot unavailable"},
    )
    tool.finish(status="error", error="slot unavailable")
    agent.status = "error"
    agent.error = SpanError(type="Error", message="ungrounded booking")
    return _finalize([agent, retrieval, llm, tool], llm.id, "llm_ungrounded_args", "llm_ungrounded_args")


def make_policy_block(rng: random.Random) -> LabeledIncident:
    agent = _agent_root("export customer PII")
    llm = SageSpan.from_kind(
        "LLM",
        "plan_export",
        parent_id=agent.id,
        outputs={"response": {"tool": "export_pii"}},
        attributes={"model": "synth-llm"},
        inputs={"prompt": "export"},
    )
    llm.finish(status="ok")
    policy = SageSpan.from_kind(
        "POLICY",
        "data_residency_check",
        parent_id=agent.id,
        inputs={"action": "export_pii", "region": rng.choice(["eu", "us"])},
        outputs={"decision": "deny"},
        data={
            "policy_name": "data_residency_check",
            "rule_id": "residency",
            "decision": "deny",
            "reason": "policy deny",
            "checked_input": {"action": "export_pii"},
        },
    )
    policy.finish(status="error", error="policy deny")
    agent.status = "error"
    agent.error = SpanError(type="Error", message="policy blocked")
    return _finalize([agent, llm, policy], policy.id, "policy_block", "policy_block")


def make_retriever_timeout_cascade(rng: random.Random) -> LabeledIncident:
    agent = _agent_root("answer with citations")
    retrieval = SageSpan.from_kind(
        "RETRIEVER",
        "vector_search",
        parent_id=agent.id,
        inputs={"query": "policy " + str(rng.randint(1, 50))},
        outputs={"error": "timeout after 8000ms", "documents": []},
        attributes={"latency_ms": 8000},
    )
    retrieval.finish(status="timeout", error="timeout")
    llm = SageSpan.from_kind(
        "LLM",
        "answer_without_context",
        parent_id=agent.id,
        inputs={"prompt": "answer"},
        outputs={"response": "I am not sure", "degraded": True},
        attributes={"confidence": 0.2, "model": "synth-llm"},
    )
    llm.finish(status="ok")
    agent.status = "error"
    agent.error = SpanError(type="Error", message="retrieval timeout cascade")
    return _finalize([agent, retrieval, llm], retrieval.id, "retriever_timeout_cascade", "retriever_timeout_cascade")


FACTORIES = {
    "stale_retrieval_schema": make_stale_retrieval_schema,
    "tool_permission_denied": make_tool_permission_denied,
    "llm_ungrounded_args": make_llm_ungrounded_args,
    "policy_block": make_policy_block,
    "retriever_timeout_cascade": make_retriever_timeout_cascade,
}


def _confounders(root_id: str, rng: random.Random) -> list[SageSpan]:
    distractors: list[SageSpan] = []
    for i in range(rng.randint(1, 3)):
        ok = SageSpan.from_kind(
            rng.choice(["CHAIN", "PROMPT", "LLM"]),
            f"distractor_{i}",
            parent_id=root_id,
            inputs={"note": "benign", "prompt": "noop"},
            outputs={"ok": True},
            attributes={"confidence": rng.random(), "model": "synth-llm"},
        )
        ok.finish(status="ok")
        ensure_typed_data(ok)
        distractors.append(ok)
    symptom = SageSpan.from_kind(
        "TOOL",
        "symptom_logger",
        parent_id=root_id,
        inputs={"mirror": True},
        outputs={"error": "downstream symptom only"},
    )
    symptom.finish(status="error", error="symptom")
    ensure_typed_data(symptom)
    distractors.append(symptom)
    fresh = SageSpan.from_kind(
        "RETRIEVER",
        "fresh_side_channel",
        parent_id=root_id,
        inputs={"query": "healthcheck"},
        outputs={"documents": [{"id": "h1", "schema_version": "v2", "fresh": True}]},
    )
    fresh.finish(status="ok")
    ensure_typed_data(fresh)
    distractors.append(fresh)
    return distractors


def generate_corpus(
    n: int,
    *,
    seed: int = 7,
    out_dir: str | Path | None = None,
    hard: bool = False,
) -> list[LabeledIncident]:
    rng = random.Random(seed)
    modes = list(FACTORIES.keys())
    items: list[LabeledIncident] = []
    for i in range(n):
        mode = modes[i % len(modes)]
        base = FACTORIES[mode](rng)
        spans = list(base.bundle.spans)
        root_id = base.root_cause_span_id
        if hard:
            spans = [spans[0], *_confounders(spans[0].span_id, rng), *spans[1:]]
        # Fresh ids
        mapping = {span.span_id: new_id("span") for span in spans}
        for span in spans:
            span.span_id = mapping[span.span_id]
            if span.parent_id in mapping:
                span.parent_id = mapping[span.parent_id]
        root_id = mapping[root_id]
        items.append(_finalize(spans, root_id, mode, base.bundle.title))

    if out_dir is not None:
        path = Path(out_dir)
        path.mkdir(parents=True, exist_ok=True)
        for item in items:
            (path / f"{item.bundle.run_id}.json").write_text(
                json.dumps(item.to_dict(), indent=2),
                encoding="utf-8",
            )
        (path / "manifest.json").write_text(
            json.dumps({"count": len(items), "seed": seed, "modes": modes}, indent=2),
            encoding="utf-8",
        )
    return items


def load_corpus(path: str | Path) -> list[LabeledIncident]:
    root = Path(path)
    if root.is_file():
        return [LabeledIncident.from_dict(json.loads(root.read_text(encoding="utf-8")))]
    items = []
    for file in sorted(root.glob("*.json")):
        if file.name == "manifest.json":
            continue
        items.append(LabeledIncident.from_dict(json.loads(file.read_text(encoding="utf-8"))))
    return items
