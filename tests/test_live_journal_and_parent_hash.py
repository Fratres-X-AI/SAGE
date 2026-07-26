from __future__ import annotations

import time

import pytest

from sage.audit import require_verified, verify_parent_content_hashes
from sage.bundle_io import load_bundle
from sage.errors import ChainIntegrityError
from sage.journal import MANIFEST_NAME, SPANS_JSONL, recover_journal
from sage.recorder import SageRecorder


def test_live_journal_appends_on_end_span_and_seals_on_finalize(tmp_path):
    journal = tmp_path / "run.journal"
    with SageRecorder(
        "live",
        blob_store=tmp_path / "blobs",
        journal_dir=journal,
        register_trace=False,
    ) as rec:
        with rec.tool_call("a", inputs={"x": 1}) as tool:
            tool.set_output(ok=True)
        assert (journal / SPANS_JSONL).exists()
        lines = (journal / SPANS_JSONL).read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        assert (journal / MANIFEST_NAME).exists()
        live_meta = __import__("json").loads((journal / MANIFEST_NAME).read_text(encoding="utf-8"))
        assert live_meta["metadata"].get("live_recording") is True
        assert live_meta["audit"]["bundle_hash"] == ""
        assert (journal / "chain.jsonl").exists()
        with rec.tool_call("b", inputs={"x": 2}) as tool:
            tool.set_output(ok=True)
    # After context exit → finalize rewrites sealed journal.
    sealed = load_bundle(journal, verify=True, rehydrate=False)
    assert sealed.audit.bundle_hash
    assert len(sealed.spans) == 2
    assert sealed.metadata.get("live_recording") is not True
    manifest = __import__("json").loads((journal / MANIFEST_NAME).read_text(encoding="utf-8"))
    assert manifest.get("manifest_seal")


def test_live_journal_crash_mid_run_recovers_prefix(tmp_path):
    journal = tmp_path / "crash.journal"
    rec = SageRecorder(
        "crashy",
        blob_store=tmp_path / "blobs",
        journal_dir=journal,
        register_trace=False,
    )
    rec.__enter__()
    with rec.tool_call("ok", inputs={"n": 1}) as tool:
        tool.set_output(ok=True)
    with rec.llm_call("mid") as llm:
        llm.set_model("m")
        llm.set_input(prompt="hi")
        llm.set_output(text="yo")
    # Simulate hard crash: no __exit__/finalize.
    report = recover_journal(journal)
    assert report.bundle is not None
    assert report.boundary is not None
    assert report.boundary.recovered_span_count >= 2


def test_parent_content_hash_mismatch_raises_chain_integrity(tmp_path):
    with SageRecorder("pch", blob_store=tmp_path / "b", register_trace=False) as rec:
        parent = rec.start_span("agent", "root")
        child = rec.start_span("tool", "child", parent_id=parent.span_id)
        rec.end_span(child.span_id, outputs={"ok": True})
        rec.end_span(parent.span_id)
    bundle = rec.finalize()
    require_verified(bundle)
    # Forge stored parent content link without rebuilding the record hash.
    for rec_row in bundle.audit.chain:
        if rec_row.get("span_id") == child.span_id:
            rec_row["parent_content_hash"] = "0" * 64
            break
    with pytest.raises(ChainIntegrityError):
        verify_parent_content_hashes(bundle)


def test_perf_gates_stream_and_concurrency(tmp_path):
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from sage.blobs import BlobStore, MemoryBudget
    from sage.concurrency import GLOBAL_TRACE_REGISTRY

    budget = MemoryBudget(limit_bytes=4 * 1024 * 1024)
    store = BlobStore(tmp_path / "blobs", memory_budget=budget, chunk_size=1024 * 1024)
    chunk = b"P" * (1024 * 1024)
    t0 = time.perf_counter()
    store.put_stream((chunk for _ in range(50)), expected_size=50 * 1024 * 1024)
    stream_s = time.perf_counter() - t0
    assert stream_s < 5.0, f"50MB stream too slow: {stream_s:.3f}s"
    assert budget.peak <= 4 * 1024 * 1024

    GLOBAL_TRACE_REGISTRY.reset()
    GLOBAL_TRACE_REGISTRY.use_file_locks = False

    def worker(i: int) -> None:
        with SageRecorder(f"p-{i}", trace_id=f"perf-{i}", blob_store=tmp_path / f"b{i}", register_trace=True) as rec:
            with rec.tool_call("t", inputs={"i": i}) as tool:
                tool.set_output(ok=True)

    t1 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=32) as pool:
        list(as_completed([pool.submit(worker, i) for i in range(32)]))
    conc_s = time.perf_counter() - t1
    GLOBAL_TRACE_REGISTRY.reset()
    GLOBAL_TRACE_REGISTRY.use_file_locks = True
    assert conc_s < 3.0, f"32-thread record too slow: {conc_s:.3f}s"
