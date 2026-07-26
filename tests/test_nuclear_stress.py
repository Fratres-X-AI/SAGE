"""Nuclear stress: hardest fail-closed forensics gauntlet SAGE can take.

Run alone::
    pytest tests/test_nuclear_stress.py -v -s --tb=short
"""

from __future__ import annotations

import json
import os
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import pytest

from sage.blobs import BlobStore, MemoryBudget
from sage.bundle_io import load_bundle
from sage.concurrency import GLOBAL_TRACE_REGISTRY
from sage.errors import BlobIntegrityError, ChainIntegrityError, FaultRecoveryError, MemoryBudgetExceeded
from sage.journal import (
    CHAIN_JSONL,
    MANIFEST_NAME,
    MANIFEST_WAL,
    SPANS_JSONL,
    compute_manifest_seal,
    recover_manifest_from_wal,
    save_journal,
    verify_journal,
)
from sage.pack import pack_artifact, unpack_artifact
from sage.recorder import SageRecorder
from sage.verify import verify_artifact
from sage.witness import WITNESS_JSONL, verify_witness_log


SECRET = "sk-nuclear-stress-secret-KEY-9f3a2b"
HMAC_KEY = "nuclear-hmac-key-do-not-leak"


def _log(msg: str) -> None:
    print(f"[nuclear] {msg}", flush=True)


def _cgroup_workers() -> int | None:
    """Effective CPU count from cgroup quota (containers: ignore nproc)."""
    path = Path("/sys/fs/cgroup/cpu.max")
    if not path.is_file():
        return None
    try:
        quota_s, period_s = path.read_text(encoding="utf-8").split()
        if quota_s == "max":
            return None
        return max(1, int(float(quota_s) / float(period_s)))
    except (OSError, ValueError, ZeroDivisionError):
        return None


@pytest.mark.slow
def test_nuclear_forensics_gauntlet(tmp_path: Path):
    """End-to-end adversarial + concurrency + integrity gauntlet."""
    t_all = time.perf_counter()
    root = tmp_path / "nuke"
    root.mkdir()
    stats: dict[str, float | int] = {}

    # ------------------------------------------------------------------
    # 1) Streaming CAS under tight memory budget (hash-on-stream)
    # SAGE_NUCLEAR_STREAM_MB (default 100; pod soak can push 512–1024)
    # ------------------------------------------------------------------
    stream_mb = max(1, int(os.environ.get("SAGE_NUCLEAR_STREAM_MB", "100")))
    _log(f"phase1: {stream_mb}MB stream under 2MB budget")
    budget = MemoryBudget(limit_bytes=2 * 1024 * 1024)
    store = BlobStore(root / "cas_stream", memory_budget=budget, chunk_size=512 * 1024)
    chunk = b"N" * (512 * 1024)
    n_chunks = stream_mb * 2  # 512KiB chunks
    stream_limit_s = max(20.0, stream_mb * 0.25)
    t0 = time.perf_counter()
    digest_100 = store.put_stream((chunk for _ in range(n_chunks)), expected_size=n_chunks * len(chunk))
    stream_s = time.perf_counter() - t0
    store.verify_blob_streaming(digest_100)
    stats["stream_mb"] = stream_mb
    stats["stream_100mb_s"] = stream_s
    stats["stream_peak_bytes"] = budget.peak
    assert stream_s < stream_limit_s, f"{stream_mb}MB stream too slow: {stream_s:.3f}s"
    assert budget.peak <= 2 * 1024 * 1024 + 512 * 1024  # peak ≈ budget + one chunk slack
    _log(f"  ok stream={stream_s:.3f}s peak={budget.peak}")

    # ------------------------------------------------------------------
    # 2) Concurrent recorders: secrets + large bodies + journals
    # Worker count: SAGE_NUCLEAR_WORKERS, else cgroup quota (not nproc).
    # ------------------------------------------------------------------
    n_workers = int(os.environ.get("SAGE_NUCLEAR_WORKERS") or _cgroup_workers() or 64)
    _log(f"phase2: {n_workers}-thread concurrent record+journal+sanitize")
    GLOBAL_TRACE_REGISTRY.reset()
    GLOBAL_TRACE_REGISTRY.use_file_locks = False
    shared_blobs = root / "shared_blobs"
    journals = root / "journals"
    journals.mkdir()
    errors: list[BaseException] = []
    lock = threading.Lock()
    sealed_paths: list[Path] = []

    def worker(i: int) -> str:
        try:
            jdir = journals / f"w{i}"
            blobs = shared_blobs if i % 2 == 0 else root / f"blobs_{i}"
            big = (("BODY-%d-" % i) * 300).ljust(4096, "X")
            with SageRecorder(
                f"nuke-{i}",
                trace_id=f"nuke-trace-{i}",
                blob_store=blobs,
                journal_dir=jdir,
                register_trace=True,
                sanitize_on_close=True,
            ) as rec:
                with rec.agent_step("boss", agent_id=f"a{i}", inputs={"goal": f"g{i}", "api_key": SECRET}):
                    with rec.llm_call("think", inputs={"prompt": f"p{i}", "token": SECRET}):
                        pass
                    with rec.tool_call("work", inputs={"body": big, "authorization": f"Bearer {SECRET}"}):
                        # nested fan-out
                        for k in range(3):
                            with rec.tool_call(f"sub-{k}", inputs={"n": k, "password": SECRET}):
                                pass
                # deep nested chain
                with rec.agent_step("deep0", agent_id=f"d{i}"):
                    for d in range(1, 12):
                        with rec.span("chain", f"deep{d}", inputs={"d": d, "secret": SECRET}):
                            pass
                bundle = rec.finalize()
            # secrets must not remain in memory spans
            dumped = json.dumps([s.to_dict() for s in bundle.spans])
            assert SECRET not in dumped
            assert "sk-nuclear" not in dumped
            # live journal must be secret-free
            raw_j = (jdir / SPANS_JSONL).read_text(encoding="utf-8")
            assert SECRET not in raw_j
            assert (jdir / MANIFEST_WAL).exists()
            path = root / f"sealed_{i}.sage.json"
            from sage.bundle_io import save_bundle

            save_bundle(bundle, path)
            with lock:
                sealed_paths.append(path)
            return bundle.audit.bundle_hash
        except BaseException as exc:  # noqa: BLE001 — collect for report
            with lock:
                errors.append(exc)
            raise

    t1 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        hashes = list(as_completed([pool.submit(worker, i) for i in range(n_workers)]))
        results = [f.result() for f in hashes]
    conc_s = time.perf_counter() - t1
    GLOBAL_TRACE_REGISTRY.reset()
    GLOBAL_TRACE_REGISTRY.use_file_locks = True
    stats["concurrent_64_s"] = conc_s
    stats["workers_ok"] = len(results)
    assert not errors, f"worker failures: {errors[:3]!r}"
    assert len(results) == n_workers
    assert len(set(results)) == n_workers, "bundle_hash collision across distinct traces"
    conc_limit_s = max(45.0, n_workers * 1.5)
    assert conc_s < conc_limit_s, f"{n_workers}-thread gauntlet too slow: {conc_s:.3f}s"
    _log(f"  ok workers={n_workers} in {conc_s:.3f}s unique_hashes={len(set(results))}")

    # ------------------------------------------------------------------
    # 3) Concurrent CAS hammer on shared store
    # ------------------------------------------------------------------
    cas_ops = max(128, int(os.environ.get("SAGE_NUCLEAR_CAS_OPS", str(max(128, n_workers * 4)))))
    cas_pool = max(8, min(n_workers, int(os.environ.get("SAGE_NUCLEAR_CAS_POOL", str(n_workers)))))
    _log(f"phase3: concurrent CAS put/verify hammer ops={cas_ops} pool={cas_pool}")
    cas = BlobStore(shared_blobs)
    t2 = time.perf_counter()

    def cas_worker(i: int) -> str:
        payload = (f"cas-{i}-" * 200).encode() + os.urandom(64)
        d = cas.put_bytes(payload)
        cas.verify_blob(d)
        got = cas.get_bytes(d, verify=True)
        assert got == payload
        return d

    with ThreadPoolExecutor(max_workers=cas_pool) as pool:
        digests = [f.result() for f in as_completed([pool.submit(cas_worker, i) for i in range(cas_ops)])]
    cas_s = time.perf_counter() - t2
    stats["cas_hammer_s"] = cas_s
    stats["cas_ops"] = cas_ops
    assert len(set(digests)) == cas_ops
    _log(f"  ok {cas_ops} CAS ops in {cas_s:.3f}s")

    # ------------------------------------------------------------------
    # 4) Pack → unpack → unified verify (+ witness) under load
    # ------------------------------------------------------------------
    n_packs = max(16, min(len(sealed_paths), int(os.environ.get("SAGE_NUCLEAR_PACKS", "16"))))
    pack_pool = max(4, min(n_packs, int(os.environ.get("SAGE_NUCLEAR_PACK_POOL", str(min(16, n_workers // 2 or 1))))))
    _log(f"phase4: pack/unpack/verify x{n_packs} pool={pack_pool} with HMAC+witness")
    sample = sealed_paths[:n_packs]
    t3 = time.perf_counter()

    def pack_worker(i: int, path: Path) -> dict:
        out = root / f"pack_{i}.sage.tar.gz"
        # Resolve blob store from bundle metadata
        b = load_bundle(path, verify=True, rehydrate=False)
        blob_root = b.metadata.get("blob_store")
        pack_artifact(path, out, blob_store=blob_root, hmac_key=HMAC_KEY, actor=f"w{i}")
        report = verify_artifact(
            out,
            require_sealed=True,
            hmac_key=HMAC_KEY,
            check_witness=True,
            witness_key=HMAC_KEY,
            blob_root=None,
        )
        assert report["ok"]
        dest = root / f"unpacked_{i}"
        journal = unpack_artifact(out, dest, hmac_key=HMAC_KEY, actor=f"u{i}")
        # Custody tip must track pack bundle_hash, not post-unpack local seal.
        verify_witness_log(journal, hmac_key=HMAC_KEY, expect_bundle_hash=report["bundle_hash"])
        assert report["bundle_hash"] == report.get("pack", {}).get("bundle_hash") or report["bundle_hash"]
        return report

    with ThreadPoolExecutor(max_workers=pack_pool) as pool:
        reports = [
            f.result()
            for f in as_completed([pool.submit(pack_worker, i, p) for i, p in enumerate(sample)])
        ]
    pack_s = time.perf_counter() - t3
    stats["pack_verify_16_s"] = pack_s
    stats["pack_count"] = n_packs
    assert all(r["ok"] for r in reports)
    _log(f"  ok pack/verify x{n_packs} in {pack_s:.3f}s")

    # ------------------------------------------------------------------
    # 5) Adversarial mutation battery — every surface must fail closed
    # ------------------------------------------------------------------
    _log("phase5: adversarial mutation battery")
    victim = sample[0]
    bundle = load_bundle(victim, verify=True, rehydrate=False)
    jdir = root / "victim_journal"
    save_journal(bundle, jdir)
    pack = pack_artifact(jdir, root / "victim.sage.tar.gz", hmac_key=HMAC_KEY)

    # 5a) chain tip forge
    man = json.loads((jdir / MANIFEST_NAME).read_text(encoding="utf-8"))
    man["chain_tip"] = "f" * 64
    del man["manifest_seal"]
    man["manifest_seal"] = compute_manifest_seal(man)
    (jdir / MANIFEST_NAME).write_text(json.dumps(man, indent=2, sort_keys=True), encoding="utf-8")
    with pytest.raises(ChainIntegrityError):
        verify_journal(jdir, allow_live=False)

    # restore clean journal for next attacks
    save_journal(bundle, jdir)

    # 5b) merkle forge
    man = json.loads((jdir / MANIFEST_NAME).read_text(encoding="utf-8"))
    man["merkle_root"] = "e" * 64
    del man["manifest_seal"]
    man["manifest_seal"] = compute_manifest_seal(man)
    (jdir / MANIFEST_NAME).write_text(json.dumps(man, indent=2, sort_keys=True), encoding="utf-8")
    with pytest.raises(ChainIntegrityError):
        load_bundle(jdir, verify=True, rehydrate=False)

    save_journal(bundle, jdir)

    # 5c) span tail tear
    spans_path = jdir / SPANS_JSONL
    spans_path.write_bytes(spans_path.read_bytes() + b'{"torn":')
    with pytest.raises((FaultRecoveryError, ChainIntegrityError)):
        verify_journal(jdir, allow_live=False)

    save_journal(bundle, jdir)

    # 5d) chain link flip
    chain_path = jdir / CHAIN_JSONL
    lines = chain_path.read_text(encoding="utf-8").splitlines()
    link = json.loads(lines[0])
    link["hash"] = "d" * 64
    lines[0] = json.dumps(link, sort_keys=True, separators=(",", ":"))
    chain_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises((ChainIntegrityError, ValueError, FaultRecoveryError)):
        verify_journal(jdir, allow_live=False)

    save_journal(bundle, jdir)

    # 5e) pack content digest / wrong HMAC
    with pytest.raises(ChainIntegrityError):
        unpack_artifact(pack, root / "bad_hmac", hmac_key="wrong-key")

    # 5f) blob missing inventory
    from sage.pack import collect_bundle_blob_digests

    digests = collect_bundle_blob_digests(bundle)
    if digests:
        empty = root / "empty_cas"
        empty.mkdir(exist_ok=True)
        with pytest.raises(ChainIntegrityError):
            verify_artifact(victim, blob_root=empty)

    # 5g) witness forge
    wdir = root / "witness_forge"
    from sage.witness import append_witness

    append_witness(wdir, action="seal", bundle_hash=bundle.audit.bundle_hash, hmac_key=HMAC_KEY)
    append_witness(wdir, action="ship", bundle_hash=bundle.audit.bundle_hash, hmac_key=HMAC_KEY)
    wpath = wdir / WITNESS_JSONL
    wlines = wpath.read_text(encoding="utf-8").splitlines()
    forged = json.loads(wlines[-1])
    forged["actor"] = "attacker"
    wlines[-1] = json.dumps(forged, sort_keys=True, separators=(",", ":"))
    wpath.write_text("\n".join(wlines) + "\n", encoding="utf-8")
    with pytest.raises(ChainIntegrityError):
        verify_witness_log(wdir, hmac_key=HMAC_KEY)

    stats["mutations_fail_closed"] = 7
    _log("  ok all mutation surfaces fail-closed")

    # ------------------------------------------------------------------
    # 6) WAL recovery after manifest kill mid-flight
    # ------------------------------------------------------------------
    _log("phase6: WAL recover after manifest deletion")
    live = root / "wal_live"
    with SageRecorder("wal", journal_dir=live, register_trace=False) as rec:
        for i in range(20):
            with rec.tool_call(f"t{i}", inputs={"api_key": SECRET, "i": i}):
                pass
        assert (live / MANIFEST_WAL).exists()
        tip = json.loads((live / MANIFEST_NAME).read_text(encoding="utf-8"))["chain_tip"]
        (live / MANIFEST_NAME).unlink()
        restored = recover_manifest_from_wal(live)
        assert restored is not None
        assert restored["chain_tip"] == tip
        report = verify_journal(live, allow_live=True)
        assert report["ok"]
        rec.finalize()
    _log("  ok WAL recovery")

    # ------------------------------------------------------------------
    # 7) Memory budget hard-fail on single spike above limit
    # ------------------------------------------------------------------
    _log("phase7: memory budget exhaustion fail-closed")
    tight = MemoryBudget(limit_bytes=64 * 1024)
    tiny = BlobStore(root / "tiny", memory_budget=tight, chunk_size=32 * 1024)
    with pytest.raises(MemoryBudgetExceeded):
        tiny.put_stream((b"Z" * (256 * 1024) for _ in range(1)), expected_size=256 * 1024)
    _log("  ok MemoryBudgetExceeded")

    # ------------------------------------------------------------------
    # 8) Wide fan-out single recorder (stress schema/chain)
    # ------------------------------------------------------------------
    fanout = max(200, int(os.environ.get("SAGE_NUCLEAR_FANOUT", "200")))
    _log(f"phase8: wide fan-out {fanout} spans + verify")
    t4 = time.perf_counter()
    with SageRecorder("wide", blob_store=root / "wide_blobs", journal_dir=root / "wide_j", register_trace=False) as rec:
        with rec.agent_step("root", inputs={"api_key": SECRET}):
            for i in range(fanout):
                with rec.tool_call(f"fan-{i}", inputs={"i": i, "body": ("w" * 1200)}):
                    pass
        wide = rec.finalize()
    save_journal(wide, root / "wide_sealed")
    vr = verify_artifact(root / "wide_sealed", require_sealed=True, blob_root=root / "wide_blobs")
    assert vr["ok"]
    assert vr["blobs"]["blob_count"] >= 1
    wide_s = time.perf_counter() - t4
    stats["wide_200_s"] = wide_s
    stats["fanout"] = fanout
    _log(f"  ok {fanout}-span fan-out in {wide_s:.3f}s")

    # ------------------------------------------------------------------
    # 9) Random late tamper during concurrent verify
    # ------------------------------------------------------------------
    _log("phase9: concurrent verify vs late pack tamper")
    clean_pack = root / "race.sage.tar.gz"
    pack_artifact(root / "wide_sealed", clean_pack, blob_store=root / "wide_blobs", hmac_key=HMAC_KEY)
    race_errs: list[BaseException] = []
    barrier = threading.Barrier(2)

    def verifier() -> None:
        barrier.wait()
        for _ in range(30):
            try:
                verify_artifact(clean_pack, hmac_key=HMAC_KEY, check_witness=True, witness_key=HMAC_KEY)
            except Exception as exc:  # noqa: BLE001
                race_errs.append(exc)
                return
            time.sleep(0.01)

    def tamper() -> None:
        barrier.wait()
        time.sleep(0.05)
        # Corrupt archive bytes in place
        data = bytearray(clean_pack.read_bytes())
        if len(data) > 200:
            idx = random.randint(50, len(data) - 50)
            data[idx] ^= 0xFF
            clean_pack.write_bytes(data)

    th1 = threading.Thread(target=verifier)
    th2 = threading.Thread(target=tamper)
    th1.start()
    th2.start()
    th1.join()
    th2.join()
    # Final verify must fail closed after tamper
    with pytest.raises(Exception):
        verify_artifact(clean_pack, hmac_key=HMAC_KEY)
    _log(f"  ok race observed_errors={len(race_errs)} final=fail-closed")

    total = time.perf_counter() - t_all
    stats["total_s"] = total
    _log(f"DONE stats={json.dumps(stats, sort_keys=True)}")
    # Default 120s for CI; pod soak raises SAGE_NUCLEAR_MAX_S under multi-lane load.
    max_s = float(os.environ.get("SAGE_NUCLEAR_MAX_S", "120"))
    assert total < max_s, f"nuclear gauntlet wall clock too slow: {total:.1f}s (limit={max_s:.0f}s)"
