from __future__ import annotations

import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

from sage.audit import require_verified, verify_audit_chain
from sage.concurrency import (
    GLOBAL_TRACE_REGISTRY,
    detect_ooo_injection,
    validate_monotonic_chain,
)
from sage.errors import ChainIntegrityError, SplitBrainError
from sage.recorder import SageRecorder
from sage.schema import SageSpan, ensure_typed_data


def _nested_agent_loop(recorder: SageRecorder, depth: int = 4, *, preempt: bool = True) -> None:
    rng = random.Random(threading.get_ident() ^ int(time.time_ns() % 1_000_000))
    with recorder.agent_step(f"agent-{threading.get_ident()}", agent_id=f"a-{threading.get_ident()}"):
        for i in range(depth):
            if preempt:
                time.sleep(rng.uniform(0, 0.0005))
            with recorder.chain(f"chain-{i}"):
                with recorder.llm_call(f"llm-{i}") as llm:
                    llm.set_model("chaos")
                    llm.set_input(prompt=f"step-{i}-{threading.get_ident()}")
                    llm.set_output(text="ok")
                with recorder.tool_call(f"tool-{i}", inputs={"n": i}) as tool:
                    tool.set_output(result=i)
            if i % 2 == 0:
                with recorder.handoff(
                    f"handoff-{i}",
                    from_agent=f"a-{threading.get_ident()}",
                    to_agent=f"b-{i}",
                    context_passed={"k": i},
                ):
                    pass


def test_32_concurrent_recorders_unique_traces_remain_verifiable(tmp_path):
    GLOBAL_TRACE_REGISTRY.reset()
    # In-process registry stress (file-lock ownership is covered separately).
    GLOBAL_TRACE_REGISTRY.use_file_locks = False
    results: list = []
    errors: list[BaseException] = []

    def worker(idx: int) -> str:
        blob_root = tmp_path / f"blobs-{idx}"
        with SageRecorder(
            f"concurrent-{idx}",
            trace_id=f"trace-unique-{idx}",
            blob_store=blob_root,
            register_trace=True,
        ) as rec:
            _nested_agent_loop(rec, depth=2, preempt=False)
            finalized = rec.finalize()
            assert verify_audit_chain(finalized)
            validate_monotonic_chain(finalized)
            require_verified(finalized)
            path = rec.export(tmp_path / f"t-{idx}.sage.json")
            return str(path)

    try:
        with ThreadPoolExecutor(max_workers=32) as pool:
            futures = [pool.submit(worker, i) for i in range(32)]
            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except BaseException as exc:  # noqa: BLE001
                    errors.append(exc)
    finally:
        GLOBAL_TRACE_REGISTRY.reset()
        GLOBAL_TRACE_REGISTRY.use_file_locks = True

    assert not errors, f"concurrent finalize errors: {errors!r}"
    assert len(results) == 32


def test_split_brain_same_trace_id_is_locked_down(tmp_path):
    GLOBAL_TRACE_REGISTRY.reset()
    GLOBAL_TRACE_REGISTRY.lock_root = str(tmp_path / "locks")
    trace = "trace-shared-hijack"
    ready = threading.Barrier(2)
    outcomes: list[str] = []
    lock = threading.Lock()

    def writer(tag: str) -> None:
        try:
            ready.wait()
            with SageRecorder(
                f"hijack-{tag}",
                trace_id=trace,
                blob_store=tmp_path / f"b-{tag}",
                register_trace=True,
            ) as rec:
                time.sleep(0.005)
                _nested_agent_loop(rec, depth=1, preempt=False)
                rec.finalize()
                with lock:
                    outcomes.append(f"ok:{tag}")
        except SplitBrainError:
            with lock:
                outcomes.append(f"split:{tag}")
        except Exception as exc:  # noqa: BLE001
            with lock:
                outcomes.append(f"err:{tag}:{type(exc).__name__}")

    t1 = threading.Thread(target=writer, args=("A",))
    t2 = threading.Thread(target=writer, args=("B",))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    GLOBAL_TRACE_REGISTRY.reset()
    GLOBAL_TRACE_REGISTRY.lock_root = None

    assert any(o.startswith("ok:") for o in outcomes)
    assert any(o.startswith("split:") for o in outcomes), outcomes


def test_out_of_order_parent_injection_flags_chain_integrity():
    with SageRecorder("ooo", register_trace=False) as rec:
        parent = rec.start_span("agent", "root")
        child = rec.start_span("tool", "child", parent_id=parent.span_id)
        rec.end_span(child.span_id, outputs={"ok": True})
        rec.end_span(parent.span_id)
        bundle = rec.finalize()

    # Craft an injected span that claims an impossible parent/seq relationship.
    injected = SageSpan(
        type="tool",
        name="hijack",
        parent_id=bundle.spans[-1].span_id,
        trace_id=bundle.bundle_id,
        inputs={},
        outputs={"x": 1},
        data={"tool_name": "hijack", "input": {}, "output": {"x": 1}, "success": True},
        attributes={"sage.seq": -1, "sage.mono_ns": 0},
    )
    ensure_typed_data(injected)
    with pytest.raises(ChainIntegrityError):
        detect_ooo_injection(bundle, injected)

    # Direct mutation: force child sage.seq <= parent sage.seq (OOO parent hashing).
    child_span = next(s for s in bundle.spans if s.name == "child")
    parent_span = next(s for s in bundle.spans if s.name == "root")
    mutant = SageSpan.from_dict(child_span.to_dict())
    mutant.attributes["sage.seq"] = int(parent_span.attributes["sage.seq"])
    mutant.attributes["sage.mono_ns"] = 0
    with pytest.raises(ChainIntegrityError):
        detect_ooo_injection(bundle, mutant)
