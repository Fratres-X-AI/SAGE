from __future__ import annotations

import copy

import pytest

from sage.audit import finalize_bundle
from sage.errors import SecurityDivergence
from sage.recorder import SageRecorder
from sage.regression import write_heal_boundary_test
from sage.replay import apply_heal
from sage.schema import SageSpan, ensure_typed_data
from sage.security import assert_heal_not_adversarial, validate_heal_boundary


def _failed_incident(tmp_path):
    with SageRecorder("heal-target", blob_store=tmp_path / "blobs", register_trace=False) as rec:
        with rec.agent_step("orch", agent_id="orch"):
            with rec.retrieval("kb", inputs={"query": "q"}) as ret:
                ret.set_output(documents=[{"id": "d1", "schema_version": "v1", "stale": True}])
                ret.set_data(
                    query="q",
                    documents=[{"id": "d1", "schema_version": "v1", "stale": True}],
                    source="kb",
                )
                ret.mark_root_cause(note="stale", score=0.9)
            with rec.tool_call("update", inputs={"schema": "v1"}) as tool:
                tool.set_output(error="schema v2 required")
                tool.fail("schema drift")
            rec.policy_decision(
                "schema-guard",
                decision="deny",
                reason="schema v1 blocked",
                inputs={"schema": "v1"},
            )
            with rec.guardrail("no-bypass", inputs={"rule": "audit"}):
                pass
        root = next(s.span_id for s in rec.bundle.spans if s.is_suspected_root_cause)
        rec.mark_failure(root, note="stale retrieval")
    path = rec.export(tmp_path / "orig.sage.json")
    from sage.bundle_io import load_bundle

    return load_bundle(path, verify=True, rehydrate=True), root


def test_rogue_patch_bypassing_validation_is_rejected(tmp_path):
    original, heal_id = _failed_incident(tmp_path)
    rogue = {
        "bypass_validation": True,
        "inject_spans": [{"span_id": "span_dummy", "parent_id": "span_forged"}],
        "skip_audit": True,
    }
    with pytest.raises(SecurityDivergence) as excinfo:
        assert_heal_not_adversarial(original, rogue)
    err = excinfo.value
    assert err.policy_span_id is not None or err.guardrail_span_id is not None
    assert "bypass" in str(err).lower() or "inject" in str(err).lower() or "validation" in str(err).lower()


def test_parent_id_falsification_breaks_heal_chain(tmp_path):
    original, heal_id = _failed_incident(tmp_path)
    healed = apply_heal(
        original,
        span_id=heal_id,
        new_data={
            "documents": [{"id": "d1", "schema_version": "v2", "fresh": True}],
            "query": "q",
        },
        new_output={"documents": [{"id": "d1", "schema_version": "v2", "fresh": True}]},
    )
    # Adversarial secondary: falsify a parent_id edge.
    tampered = copy.deepcopy(healed)
    # Point a non-root span at a fabricated parent.
    for span in tampered.spans:
        if span.span_id != heal_id and span.parent_id is not None:
            span.parent_id = "span_forged_parent"
            break
    # Re-finalize would fail parent integrity; we simulate a rogue writer skipping that.
    tampered.metadata["healed_from_bundle_id"] = original.bundle_id
    tampered.metadata["healed_span_id"] = heal_id

    with pytest.raises(SecurityDivergence) as excinfo:
        validate_heal_boundary(original, tampered, heal_span_id=heal_id)
    assert "parent_id" in str(excinfo.value).lower()

    with pytest.raises(SecurityDivergence):
        write_heal_boundary_test(
            original,
            tampered,
            tmp_path / "generated",
            heal_span_id=heal_id,
        )


def test_dummy_span_injection_flagged_as_security_divergence(tmp_path):
    original, heal_id = _failed_incident(tmp_path)
    healed = apply_heal(
        original,
        span_id=heal_id,
        new_data={
            "documents": [{"id": "d1", "schema_version": "v2"}],
            "query": "q",
        },
        new_output={"documents": [{"id": "d1", "schema_version": "v2"}]},
    )
    poisoned = copy.deepcopy(healed)
    dummy = SageSpan(
        type="tool",
        name="dummy-injector",
        span_id="span_dummy_adversary",
        parent_id=heal_id,
        trace_id=poisoned.bundle_id,
        inputs={"exploit": True},
        outputs={"ok": True},
        data={
            "tool_name": "dummy-injector",
            "input": {"exploit": True},
            "output": {"ok": True},
            "success": True,
        },
    )
    ensure_typed_data(dummy)
    poisoned.spans.append(dummy)
    poisoned.metadata["healed_from_bundle_id"] = original.bundle_id
    poisoned.metadata["healed_span_id"] = heal_id
    poisoned.metadata["secondary_failure"] = True

    with pytest.raises(SecurityDivergence) as excinfo:
        write_heal_boundary_test(
            original,
            poisoned,
            tmp_path / "gen-inject",
            heal_span_id=heal_id,
        )
    assert excinfo.value.details.get("injected_span_ids") == ["span_dummy_adversary"]
    assert excinfo.value.policy_span_id or excinfo.value.guardrail_span_id


def test_legitimate_secondary_boundary_still_writes(tmp_path):
    original, heal_id = _failed_incident(tmp_path)
    tool_id = next(s.span_id for s in original.spans if s.type == "tool")
    secondary = apply_heal(
        original,
        span_id=heal_id,
        new_data={
            "documents": [{"id": "d1", "schema_version": "v2", "fresh": True}],
            "query": "q",
        },
        new_output={"documents": [{"id": "d1", "schema_version": "v2", "fresh": True}]},
        secondary_mutations=[
            {
                "span_id": tool_id,
                "status": "error",
                "error": "post-heal auth regression",
                "outputs": {"error": "unauthorized"},
            }
        ],
    )
    validate_heal_boundary(original, secondary, heal_span_id=heal_id, allow_secondary_failure=True)
    paths = write_heal_boundary_test(
        original,
        secondary,
        tmp_path / "gen-ok",
        heal_span_id=heal_id,
    )
    assert paths[0].exists() and paths[1].exists()
