from __future__ import annotations

from pathlib import Path

import pytest

from sage.blobs import BlobStore, MemoryBudget
from sage.bundle_io import load_bundle, save_bundle
from sage.errors import BlobIntegrityError, SecurityDivergence, SplitBrainError
from sage.heal_capability import HealCapability, HealPatch
from sage.journal import SPANS_JSONL, recover_journal, save_journal
from sage.locks import TraceFileLock
from sage.recorder import SageRecorder
from sage.replay import apply_heal
from sage.security import validate_heal_boundary


def test_cross_process_file_lock_rejects_second_owner(tmp_path):
    """O_EXCL lockfile is the cross-process source of truth (same path two owners)."""
    lock_root = tmp_path / "locks"
    trace = "trace-cross-proc"
    parent = TraceFileLock(trace, root=lock_root, owner="parent")
    parent.acquire()
    assert parent.path.exists()
    hijacker = TraceFileLock(trace, root=lock_root, owner="hijacker-pid-99999")
    with pytest.raises(SplitBrainError):
        hijacker.acquire()
    parent.release()
    # After release, a new owner may acquire.
    successor = TraceFileLock(trace, root=lock_root, owner="successor")
    successor.acquire()
    successor.release()


def test_streaming_verify_does_not_require_full_buffer_for_integrity(tmp_path):
    budget = MemoryBudget(limit_bytes=2 * 1024 * 1024)
    store = BlobStore(tmp_path / "blobs", memory_budget=budget, chunk_size=256 * 1024, compress=True)
    chunk = b"V" * (256 * 1024)
    digest = store.put_stream((chunk for _ in range(20)), expected_size=20 * 256 * 1024)
    # Streaming verify under budget.
    size = store.verify_blob_streaming(digest)
    assert size == 20 * 256 * 1024
    assert budget.peak <= 2 * 1024 * 1024
    # Tamper → streaming verify hard-fails.
    path = tmp_path / "blobs" / f"{digest}.gz"
    if not path.exists():
        path = tmp_path / "blobs" / digest
    path.write_bytes(path.read_bytes()[:100] + b"\x00\xff" + path.read_bytes()[102:])
    with pytest.raises(BlobIntegrityError):
        store.verify_blob_streaming(digest)


def test_torn_jsonl_journal_recovers_prefix(tmp_path):
    with SageRecorder("journal", blob_store=tmp_path / "b", register_trace=False) as rec:
        for i in range(12):
            with rec.tool_call(f"t-{i}", inputs={"i": i}) as tool:
                tool.set_output(ok=True)
        bundle = rec.finalize()
    root = tmp_path / "jdir"
    save_journal(bundle, root)
    spans_path = root / SPANS_JSONL
    raw = spans_path.read_bytes()
    # Tear the final line mid-object.
    cut = raw.rfind(b"\n", 0, len(raw) - 2)
    spans_path.write_bytes(raw[:cut] + b'\n{"span_id": "torn", "type": "tool", "name": "x"')
    report = recover_journal(root)
    assert report.ok is False
    assert report.boundary is not None
    assert report.boundary.truncated is True
    assert report.boundary.recovered_span_count >= 1
    assert report.boundary.failure_anchor["kind"] == "crash_boundary"
    assert report.bundle is not None


def test_journal_roundtrip_verifies(tmp_path):
    with SageRecorder("j2", blob_store=tmp_path / "b2", register_trace=False) as rec:
        with rec.llm_call("c") as span:
            span.set_model("m")
            span.set_input(prompt="hi")
            span.set_output(text="yo")
        bundle = rec.finalize()
    root = tmp_path / "journal_out"
    save_bundle(bundle, root, format="journal")
    loaded = load_bundle(root, verify=True, rehydrate=False)
    assert loaded.audit.bundle_hash == bundle.audit.bundle_hash
    assert loaded.audit.chain[0].get("content_hash")
    assert "parent_content_hash" in loaded.audit.chain[0]


def test_forged_heal_capability_seal_is_rejected(tmp_path):
    root_id: str
    with SageRecorder("heal", blob_store=tmp_path / "bh", register_trace=False) as rec:
        with rec.retrieval("kb", inputs={"query": "q"}) as ret:
            ret.set_output(documents=[{"schema_version": "v1"}])
            ret.set_data(query="q", documents=[{"schema_version": "v1"}], source="kb")
            ret.mark_root_cause(note="stale")
            root_id = ret.span.span_id
        with rec.tool_call("t", inputs={}) as tool:
            tool.fail("schema drift")
        rec.mark_failure(root_id, note="stale")
    original = rec.finalized_bundle()
    healed = apply_heal(
        original,
        span_id=root_id,
        new_data={"documents": [{"schema_version": "v2"}], "query": "q"},
        new_output={"documents": [{"schema_version": "v2"}]},
    )
    healed.metadata["heal_capability"]["seal"] = "0" * 64
    with pytest.raises(SecurityDivergence):
        validate_heal_boundary(original, healed, heal_span_id=root_id)


def test_heal_patch_escape_via_extra_span_blocked(tmp_path):
    with SageRecorder("esc", blob_store=tmp_path / "be", register_trace=False) as rec:
        with rec.tool_call("a", inputs={"x": 1}) as a:
            a.fail("boom")
        with rec.tool_call("b", inputs={"x": 2}) as b:
            b.set_output(ok=True)
        rec.mark_failure(a.span.span_id, note="a")
    original = rec.finalize()
    heal_id = original.root_cause_hint
    assert isinstance(heal_id, str)
    cap = HealCapability.issue(original, heal_span_id=heal_id)
    other = next(s.span_id for s in original.spans if s.span_id != heal_id)
    patch = HealPatch(
        capability=cap,
        primary_span_id=heal_id,
        mutations=[
            {"span_id": heal_id, "status": "ok", "error": None},
            {"span_id": other, "status": "error", "error": "injected"},
        ],
    )
    with pytest.raises(SecurityDivergence):
        patch.validate()
