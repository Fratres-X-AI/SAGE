from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

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
        rec.flush_journal()  # default durability is "batch": commit before reading the live files
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
    # Simulate hard crash: no __exit__/finalize. (Real process kills are tested below.)
    rec.flush_journal()
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


# --- Durability modes -------------------------------------------------------------------------------

MODES = ("span", "batch", "close")


def _writer_stopped(rec: SageRecorder) -> bool:
    """True when the recorder's journal writer has no background thread."""
    writer = rec._journal_writer
    return writer is not None and writer._thread is None


def _child_env() -> dict[str, str]:
    import sage

    env = dict(os.environ)
    src = str(Path(sage.__file__).resolve().parents[1])
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    env.pop("SAGE_JOURNAL_DURABILITY", None)
    return env


def _assert_recovered_prefix_verifies(journal: Path, blobs: Path, *, at_least: int, at_most: int) -> int:
    """Recover the journal of a dead process and prove the prefix is intact and re-sealable."""
    from sage.blobs import BlobStore, is_blob_ref
    from sage.journal import attach_enriched_audit, verify_live_chain_prefix

    report = recover_journal(journal)
    assert report.bundle is not None, report.errors
    assert report.boundary is not None
    count = report.boundary.recovered_span_count
    assert at_least <= count <= at_most, f"recovered {count}, expected {at_least}..{at_most}"
    bundle = report.bundle
    # The recovered spans are exactly the first `count` spans the process closed, in order.
    assert [s.name for s in bundle.spans] == [f"s{i}" for i in range(count)]
    # The chain written by the dead process recomputes; it was not rebuilt.
    assert bundle.metadata["chain_rebuilt"] is False
    verify_live_chain_prefix([s.to_dict() for s in bundle.spans], bundle.audit.chain)
    # Every blob a recovered span refers to is present and intact (blobs are fsynced first).
    store = BlobStore(blobs)
    for span in bundle.spans:
        ref = span.inputs["big"]
        assert is_blob_ref(ref)
        store.verify_blob(ref["$sage_blob"])
    # And the prefix seals into a bundle that passes full verification.
    require_verified(attach_enriched_audit(bundle))
    return count


_EXIT_CHILD = """
import os, sys
from sage.recorder import SageRecorder

journal, blobs, mode = sys.argv[1:4]
rec = SageRecorder(
    "crash", trace_id="crash-" + mode, blob_store=blobs, journal_dir=journal, register_trace=False,
    journal_durability=mode, journal_batch_interval_ms=600000, journal_batch_max_spans=100000,
)
rec.__enter__()

def record(i):
    with rec.tool_call("s%d" % i, inputs={"i": i, "big": "x" * 2000 + str(i)}) as tool:
        tool.set_output(ok=True)

for i in range(20):
    record(i)
rec.flush_journal()
for i in range(20, 30):
    record(i)
os._exit(17)  # hard exit: no seal, no atexit handlers, no thread joins
"""


@pytest.mark.parametrize("mode", MODES)
def test_crash_by_hard_exit_recovers_committed_prefix(tmp_path, mode):
    """`os._exit` mid-run. 20 spans were flushed; 10 more were closed but, in batch and close mode,
    were still queued (the group commit is set far in the future)."""
    journal, blobs = tmp_path / "j", tmp_path / "blobs"
    proc = subprocess.run(
        [sys.executable, "-c", _EXIT_CHILD, str(journal), str(blobs), mode],
        env=_child_env(), capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 17, proc.stderr
    expected = 30 if mode == "span" else 20
    _assert_recovered_prefix_verifies(journal, blobs, at_least=expected, at_most=expected)
    # The dead process left a consistent live journal, so it also verifies as-is.
    from sage.journal import verify_journal

    report = verify_journal(journal, allow_live=True)
    assert report["live"] is True and report["span_count"] == expected


_NO_SEAL_CHILD = """
import sys
from sage.recorder import SageRecorder

journal, blobs, mode = sys.argv[1:4]
rec = SageRecorder(
    "noseal", trace_id="noseal-" + mode, blob_store=blobs, journal_dir=journal, register_trace=False,
    journal_durability=mode, journal_batch_interval_ms=600000, journal_batch_max_spans=100000,
)
rec.__enter__()
for i in range(12):
    with rec.tool_call("s%d" % i, inputs={"i": i, "big": "x" * 2000 + str(i)}) as tool:
        tool.set_output(ok=True)
# Normal interpreter exit without a seal: the writer commits what is queued on the way out.
"""


@pytest.mark.parametrize("mode", MODES)
def test_normal_exit_without_seal_commits_queued_spans(tmp_path, mode):
    journal, blobs = tmp_path / "j", tmp_path / "blobs"
    proc = subprocess.run(
        [sys.executable, "-c", _NO_SEAL_CHILD, str(journal), str(blobs), mode],
        env=_child_env(), capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr.strip() == "", proc.stderr
    _assert_recovered_prefix_verifies(journal, blobs, at_least=12, at_most=12)


_KILL_CHILD = """
import sys
from sage.recorder import SageRecorder

journal, blobs, mode = sys.argv[1:4]
rec = SageRecorder(
    "kill", trace_id="kill-" + mode, blob_store=blobs, journal_dir=journal, register_trace=False,
    journal_durability=mode, journal_batch_interval_ms=5, journal_batch_max_spans=8,
)
rec.__enter__()
i = 0
while True:
    with rec.tool_call("s%d" % i, inputs={"i": i, "big": "x" * 2000 + str(i)}) as tool:
        tool.set_output(ok=True)
    i += 1
    if i == 25:
        rec.flush_journal()
        print("ready", flush=True)
"""


@pytest.mark.parametrize("mode", MODES)
def test_crash_by_kill_mid_write_recovers_verified_prefix(tmp_path, mode):
    """Kill the process while it is recording and the writer is committing."""
    journal, blobs = tmp_path / "j", tmp_path / "blobs"
    proc = subprocess.Popen(
        [sys.executable, "-c", _KILL_CHILD, str(journal), str(blobs), mode],
        env=_child_env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        assert proc.stdout is not None
        line = proc.stdout.readline()
        assert line.strip() == "ready", proc.stderr.read() if proc.stderr else ""
        time.sleep(0.15)
    finally:
        proc.kill()
        proc.communicate(timeout=60)
    # Everything flushed before "ready" survives; whatever else survived is a contiguous prefix.
    _assert_recovered_prefix_verifies(journal, blobs, at_least=25, at_most=10**9)


@pytest.mark.parametrize("mode", MODES)
def test_seal_flushes_and_joins_writer_in_every_mode(tmp_path, mode):
    journal = tmp_path / "j"
    with SageRecorder(
        "seal", blob_store=tmp_path / "blobs", journal_dir=journal, register_trace=False,
        journal_durability=mode, journal_batch_interval_ms=600_000,
    ) as rec:
        for i in range(40):
            with rec.tool_call(f"s{i}", inputs={"i": i}) as tool:
                tool.set_output(ok=True)
    assert rec._journal_writer.closed
    assert _writer_stopped(rec)
    sealed = load_bundle(journal, verify=True, rehydrate=False)
    assert len(sealed.spans) == 40
    manifest = json.loads((journal / MANIFEST_NAME).read_text(encoding="utf-8"))
    assert manifest.get("manifest_seal")


@pytest.mark.parametrize("mode", MODES)
def test_flush_journal_leaves_a_verifiable_live_journal(tmp_path, mode):
    from sage.journal import verify_journal

    journal = tmp_path / "j"
    with SageRecorder(
        "flush", blob_store=tmp_path / "blobs", journal_dir=journal, register_trace=False,
        journal_durability=mode, journal_batch_interval_ms=600_000,
    ) as rec:
        for i in range(10):
            with rec.tool_call(f"s{i}", inputs={"i": i}) as tool:
                tool.set_output(ok=True)
        rec.flush_journal()
        report = verify_journal(journal, allow_live=True)
        assert report["live"] is True and report["span_count"] == 10


def test_batch_mode_group_commits_and_replaces_manifest_only_on_flush(tmp_path):
    journal = tmp_path / "j"
    with SageRecorder(
        "group", blob_store=tmp_path / "blobs", journal_dir=journal, register_trace=False,
        journal_durability="batch", journal_batch_interval_ms=600_000, journal_batch_max_spans=100_000,
    ) as rec:
        for i in range(200):
            with rec.tool_call(f"s{i}", inputs={"i": i}) as tool:
                tool.set_output(ok=True)
        # Nothing but the start-of-run manifest is on disk until a commit happens.
        assert not (journal / SPANS_JSONL).exists()
        start = json.loads((journal / MANIFEST_NAME).read_text(encoding="utf-8"))
        assert start["chain_tip"] == "0" * 64
        rec.flush_journal()
        wal = (journal / "manifest.wal.jsonl").read_text(encoding="utf-8").splitlines()
        assert len(wal) == 2  # recording start + one group commit for 200 spans
        assert len((journal / SPANS_JSONL).read_text(encoding="utf-8").splitlines()) == 200
        assert json.loads((journal / MANIFEST_NAME).read_text(encoding="utf-8"))["span_count"] == 200


def test_batch_mode_commits_within_its_interval_without_a_flush(tmp_path):
    journal = tmp_path / "j"
    with SageRecorder(
        "interval", blob_store=tmp_path / "blobs", journal_dir=journal, register_trace=False,
        journal_durability="batch", journal_batch_interval_ms=20,
    ) as rec:
        with rec.tool_call("s0", inputs={"i": 0}) as tool:
            tool.set_output(ok=True)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            manifest = json.loads((journal / MANIFEST_NAME).read_text(encoding="utf-8"))
            if manifest["span_count"] == 1 and manifest["chain_tip"] != "0" * 64:
                break
            time.sleep(0.01)
        else:
            pytest.fail("the background writer did not commit the span")


def test_reader_polling_the_live_manifest_does_not_fail_the_writer(tmp_path):
    import threading

    journal = tmp_path / "j"
    stop = threading.Event()

    def poll() -> None:
        while not stop.is_set():
            try:
                with open(journal / MANIFEST_NAME, "rb") as handle:  # a slow reader keeps it open
                    handle.read()
                    time.sleep(0.005)
            except OSError:
                pass
            time.sleep(0.005)

    with SageRecorder(
        "polled", blob_store=tmp_path / "blobs", journal_dir=journal, register_trace=False,
        journal_durability="batch", journal_batch_interval_ms=1,
    ) as rec:
        reader = threading.Thread(target=poll, daemon=True)
        reader.start()
        try:
            for i in range(60):
                with rec.tool_call(f"s{i}", inputs={"i": i}) as tool:
                    tool.set_output(ok=True)
                time.sleep(0.002)
            rec.flush_journal()
        finally:
            stop.set()
            reader.join()
        manifest = json.loads((journal / MANIFEST_NAME).read_text(encoding="utf-8"))
        assert manifest["span_count"] == 60


def test_span_mode_is_on_disk_when_end_span_returns(tmp_path):
    from sage.journal import verify_journal

    journal = tmp_path / "j"
    with SageRecorder(
        "sync", blob_store=tmp_path / "blobs", journal_dir=journal, register_trace=False,
        journal_durability="span",
    ) as rec:
        for i in range(3):
            with rec.tool_call(f"s{i}", inputs={"i": i}) as tool:
                tool.set_output(ok=True)
            assert verify_journal(journal, allow_live=True)["span_count"] == i + 1
        assert _writer_stopped(rec)  # span mode never starts a thread


def test_writer_thread_failure_surfaces_and_is_not_swallowed(tmp_path, monkeypatch):
    import sage.journal as journal_module
    from sage.errors import JournalWriteError

    real_commit = journal_module._commit_live_records

    def failing_commit(root, records, snapshot, *, fsync):
        if records:
            raise OSError(28, "No space left on device")
        return real_commit(root, records, snapshot, fsync=fsync)

    monkeypatch.setattr(journal_module, "_commit_live_records", failing_commit)
    rec = SageRecorder(
        "boom", blob_store=tmp_path / "blobs", journal_dir=tmp_path / "j", register_trace=False,
        journal_durability="batch", journal_batch_interval_ms=1,
    )
    with pytest.raises(JournalWriteError) as raised:
        with rec:
            with rec.tool_call("s0", inputs={"i": 0}) as tool:
                tool.set_output(ok=True)
            # The failure happens on the writer thread; it must reach the recording thread.
            with pytest.raises(JournalWriteError, match="No space left"):
                rec.flush_journal()
            with pytest.raises(JournalWriteError):
                with rec.tool_call("s1", inputs={"i": 1}):
                    pass
    assert isinstance(raised.value.__cause__, OSError)
    assert _writer_stopped(rec)


def test_writer_failure_does_not_mask_an_exception_from_the_run(tmp_path, monkeypatch):
    import sage.journal as journal_module

    def failing_commit(root, records, snapshot, *, fsync):
        if records:
            raise OSError("disk gone")

    monkeypatch.setattr(journal_module, "_commit_live_records", failing_commit)
    with pytest.raises(KeyError):
        with SageRecorder(
            "mask", blob_store=tmp_path / "blobs", journal_dir=tmp_path / "j", register_trace=False,
            journal_durability="batch",
        ) as rec:
            with rec.tool_call("s0", inputs={"i": 0}) as tool:
                tool.set_output(ok=True)
            raise KeyError("the run failed first")
    assert _writer_stopped(rec)


@pytest.mark.parametrize("mode", MODES)
def test_concurrent_end_span_keeps_the_chain_consistent(tmp_path, mode):
    from sage.journal import verify_journal

    journal = tmp_path / "j"
    threads, per_thread = 6, 25
    with SageRecorder(
        "threads", blob_store=tmp_path / "blobs", journal_dir=journal, register_trace=False,
        journal_durability=mode, journal_batch_interval_ms=2, journal_batch_max_spans=16,
    ) as rec:
        root = rec.start_span("agent", "root")
        errors: list[BaseException] = []

        def work(worker: int) -> None:
            try:
                for i in range(per_thread):
                    span = rec.start_span("tool", f"w{worker}-{i}", parent_id=root.span_id, inputs={"i": i})
                    rec.end_span(span.span_id, outputs={"ok": True})
            except BaseException as exc:  # pragma: no cover - reported below
                errors.append(exc)

        pool = [threading.Thread(target=work, args=(w,)) for w in range(threads)]
        for t in pool:
            t.start()
        for t in pool:
            t.join()
        assert not errors, errors
        rec.end_span(root.span_id)
        rec.flush_journal()
        live = verify_journal(journal, allow_live=True)
        assert live["span_count"] == threads * per_thread + 1
    sealed = load_bundle(journal, verify=True, rehydrate=False)
    assert len(sealed.spans) == threads * per_thread + 1


def test_backpressure_bounds_uncommitted_spans(tmp_path, monkeypatch):
    import sage.journal as journal_module
    from sage.journal import LiveJournalWriter

    real_commit = journal_module._commit_live_records

    def slow_commit(root, records, snapshot, *, fsync):
        time.sleep(0.02)
        return real_commit(root, records, snapshot, fsync=fsync)

    monkeypatch.setattr(journal_module, "_commit_live_records", slow_commit)
    writer = LiveJournalWriter(
        tmp_path / "j", durability="batch", batch_interval_ms=1, batch_max_spans=2, max_uncommitted=4
    )
    worst = 0
    for i in range(40):
        writer.append(json.dumps({"i": i}), json.dumps({"link": i}), None)
        worst = max(worst, len(writer._pending) + writer._in_flight)
    writer.close()
    assert worst <= 4
    lines = (tmp_path / "j" / SPANS_JSONL).read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["i"] for line in lines] == list(range(40))
    assert writer.commits > 1


def test_durability_option_validation_and_environment_default(tmp_path, monkeypatch):
    from sage.journal import DEFAULT_DURABILITY, resolve_durability

    assert DEFAULT_DURABILITY == "batch"
    monkeypatch.delenv("SAGE_JOURNAL_DURABILITY", raising=False)
    assert SageRecorder("d", register_trace=False, blob_store=tmp_path / "b").journal_durability == "batch"
    monkeypatch.setenv("SAGE_JOURNAL_DURABILITY", "span")
    assert resolve_durability(None) == "span"
    assert SageRecorder("d", register_trace=False, blob_store=tmp_path / "b").journal_durability == "span"
    # An explicit argument wins over the environment.
    assert resolve_durability("close") == "close"
    with pytest.raises(ValueError, match="unknown journal durability"):
        SageRecorder("d", register_trace=False, blob_store=tmp_path / "b", journal_durability="never")
    with pytest.raises(ValueError):
        SageRecorder("d", register_trace=False, blob_store=tmp_path / "b", journal_batch_max_spans=0)


def test_deferred_blob_gets_its_final_name_only_after_fsync(tmp_path):
    from sage.blobs import BlobStore

    store = BlobStore(tmp_path / "blobs")
    digest = store.put_text("z" * 5000, sync=False)
    assert not (tmp_path / "blobs" / digest).exists()  # still under a temp name
    assert store.exists(digest)
    assert store.get_text(digest) == "z" * 5000  # readable and verified through the same store
    assert store.put_text("z" * 5000, sync=False) == digest  # dedup against the pending object
    assert store.sync_pending() == 1
    assert (tmp_path / "blobs" / digest).exists()
    assert BlobStore(tmp_path / "blobs").get_text(digest) == "z" * 5000
    assert store.sync_pending() == 0
    # A durable write of a pending object makes it durable immediately.
    other = store.put_text("q" * 5000, sync=False)
    assert store.put_text("q" * 5000) == other
    assert (tmp_path / "blobs" / other).exists()
    leftovers = [p.name for p in (tmp_path / "blobs").iterdir() if p.name.startswith(".sage-blob-")]
    assert leftovers == []


@pytest.mark.parametrize("mode", MODES)
def test_blobs_are_in_place_once_the_journal_names_them(tmp_path, mode):
    from sage.blobs import BlobStore

    journal, blobs = tmp_path / "j", tmp_path / "blobs"
    with SageRecorder(
        "blobs", blob_store=blobs, journal_dir=journal, register_trace=False,
        journal_durability=mode, journal_batch_interval_ms=600_000,
    ) as rec:
        with rec.tool_call("s0", inputs={"big": "b" * 4000}) as tool:
            tool.set_output(ok=True)
        rec.flush_journal()
        line = json.loads((journal / SPANS_JSONL).read_text(encoding="utf-8").splitlines()[0])
        digest = line["inputs"]["big"]["$sage_blob"]
        # A separate store instance (another process, a packer) can read it.
        assert BlobStore(blobs).get_text(digest) == "b" * 4000

