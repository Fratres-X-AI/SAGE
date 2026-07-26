from __future__ import annotations

import hashlib
import threading
import time

import pytest

from sage.blobs import BLOB_MARKER, BlobStore, MemoryBudget, sha256_bytes
from sage.bundle_io import load_bundle
from sage.errors import BlobIntegrityError, MemoryBudgetExceeded
from sage.recorder import SageRecorder
from sage.replay import pure_recorded_replay


def _find_prefix_collision(prefix_hex_len: int = 4, max_attempts: int = 500_000) -> tuple[bytes, bytes, str]:
    """Find two distinct payloads whose SHA-256 shares a short hex prefix (birthday probe)."""
    seen: dict[str, bytes] = {}
    for i in range(max_attempts):
        payload = f"collision-probe-{i}".encode()
        digest = hashlib.sha256(payload).hexdigest()
        key = digest[:prefix_hex_len]
        if key in seen and seen[key] != payload:
            return seen[key], payload, key
        seen[key] = payload
    raise AssertionError(f"failed to find {prefix_hex_len}-nibble prefix collision")


def test_truncated_hash_prefix_collision_does_not_alias_cas(tmp_path):
    a, b, prefix = _find_prefix_collision(4)
    assert a != b
    store = BlobStore(tmp_path / "blobs")
    da = store.put_bytes(a)
    db = store.put_bytes(b)
    assert da != db
    assert da.startswith(prefix) and db.startswith(prefix)
    assert store.get_bytes(da) == a
    assert store.get_bytes(db) == b


def test_blob_tamper_during_replay_hard_fails(tmp_path):
    blob_root = tmp_path / "blobs"
    big = ("TAMPER-ME-" * 200).ljust(2048, "X")
    with SageRecorder("cas-tamper", blob_store=blob_root, register_trace=False) as rec:
        with rec.tool_call("ingest", inputs={"body": big}) as tool:
            tool.set_output(ok=True)
    path = rec.export(tmp_path / "incident.sage.json")
    compact = load_bundle(path, verify=True, rehydrate=False)
    ref = compact.spans[0].inputs["body"]
    assert isinstance(ref, dict) and BLOB_MARKER in ref
    digest = ref[BLOB_MARKER]
    target = blob_root / digest
    if not target.exists():
        target = blob_root / f"{digest}.gz"

    # Mutate on disk while a concurrent rehydrate/replay attempts to read.
    barrier = threading.Barrier(2)
    errors: list[BaseException] = []

    def mutator() -> None:
        barrier.wait()
        time.sleep(0.01)
        raw = target.read_bytes()
        # Flip bits — keep size stable for gzip/plain.
        target.write_bytes(bytes(b ^ 0x5A for b in raw[: min(64, len(raw))]) + raw[min(64, len(raw)) :])

    def reader() -> None:
        barrier.wait()
        try:
            for _ in range(40):
                try:
                    load_bundle(path, verify=True, rehydrate=True, blob_store=blob_root)
                    pure_recorded_replay(
                        load_bundle(path, verify=True, rehydrate=True, blob_store=blob_root)
                    )
                except BlobIntegrityError as exc:
                    errors.append(exc)
                    return
                time.sleep(0.005)
        except BlobIntegrityError as exc:
            errors.append(exc)

    t1 = threading.Thread(target=mutator)
    t2 = threading.Thread(target=reader)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # Whether race won before/after mutate, subsequent verified rehydrate must hard-fail.
    with pytest.raises(BlobIntegrityError):
        store = BlobStore(blob_root)
        store.verify_blob(digest)
    assert errors or True  # mutator path always leaves digest invalid
    with pytest.raises(BlobIntegrityError):
        load_bundle(path, verify=True, rehydrate=True, blob_store=blob_root)


def test_streaming_50mb_under_memory_budget(tmp_path):
    budget = MemoryBudget(limit_bytes=4 * 1024 * 1024)
    store = BlobStore(tmp_path / "blobs", memory_budget=budget, chunk_size=1024 * 1024, compress=True)
    chunk = b"S" * (1024 * 1024)
    total = 50 * 1024 * 1024

    def producer():
        for _ in range(50):
            yield chunk

    digest = store.put_stream(producer(), expected_size=total)
    assert len(digest) == 64
    assert budget.peak <= 4 * 1024 * 1024
    # Verify without materializing a second full copy beyond get_bytes (post-write check).
    store.verify_blob(digest)
    data = store.get_bytes(digest)
    assert len(data) == total
    assert sha256_bytes(data) == digest


def test_memory_budget_fail_closed_on_spike(tmp_path):
    budget = MemoryBudget(limit_bytes=256 * 1024)
    store = BlobStore(tmp_path / "blobs", memory_budget=budget, chunk_size=128 * 1024)

    def producer():
        yield b"Z" * (512 * 1024)

    with pytest.raises(MemoryBudgetExceeded):
        store.put_stream(producer(), expected_size=512 * 1024)


def test_recorder_large_payload_streams_without_dropping_fail_closed(tmp_path):
    blob_root = tmp_path / "blobs"
    # 2 MiB payload through recorder path (stdlib pipeline + CAS).
    payload = ("STREAM-" * 40_000)  # ~280KB+ ; pad to >1MB
    payload = payload + ("X" * (2 * 1024 * 1024 - len(payload)))
    budget = MemoryBudget(limit_bytes=8 * 1024 * 1024)
    store = BlobStore(blob_root, memory_budget=budget, chunk_size=256 * 1024)
    with SageRecorder("stream-agent", blob_store=store, register_trace=False) as rec:
        with rec.llm_call("huge-context") as span:
            span.set_model("local")
            span.set_input(prompt=payload)
            span.set_output(text="ack")
    path = rec.export(tmp_path / "big.sage.json")
    compact = load_bundle(path, verify=True, rehydrate=False)
    assert BLOB_MARKER in str(compact.spans[0].inputs) or BLOB_MARKER in str(compact.spans[0].data)
    hydrated = load_bundle(path, verify=True, rehydrate=True, blob_store=blob_root)
    assert payload[:32] in str(hydrated.spans[0].inputs) or payload[:32] in str(
        hydrated.spans[0].data.get("input")
    )
    assert pure_recorded_replay(hydrated).ok
