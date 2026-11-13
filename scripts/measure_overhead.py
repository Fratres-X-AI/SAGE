#!/usr/bin/env python3
"""Measure SAGE recording overhead (local measurement, not an SLA). Output is JSON.

Two modes:

    # Synthetic consultancy workflow through the LangChain callback (needs the [langchain] extra)
    python scripts/measure_overhead.py --runs 100 --warmup 10 --durability batch --out overhead.json

    # Per-span journal cost, swept over payload sizes and durability modes (stdlib only)
    python scripts/measure_overhead.py --mode journal --durability all --spans 2000 \
        --payload-bytes 64,512,4096,32768 --out journal.json

`workflow` reports median and p95 for the uninstrumented workflow, the same workflow recorded
through the LangChain callback (live journal on), and, separately, seal + pack + verify time, plus
span count, recorded input size, and pack size.

`journal` reports, for every durability mode and payload size, the median and p95 time to record
one closed span (`end_span` latency as the caller sees it), the time to seal, and the end-to-end
time per span including the seal. Each span carries a unique payload of the given size, so a
payload above the 1 KiB offload threshold writes one new blob per span (the worst case).
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples"))

os.environ.setdefault("LANGCHAIN_TRACING_V2", "false")
os.environ.setdefault("LANGSMITH_TRACING", "false")


def _stats(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    p95 = ordered[min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1))))]
    return {"median_ms": round(statistics.median(ordered) * 1000, 3), "p95_ms": round(p95 * 1000, 3), "n": len(ordered)}


DURABILITY_MODES = ("span", "batch", "close")
NOTE = "Local measurement on a synthetic workload. Not a production SLA."


def _environment() -> dict[str, object]:
    import sage

    return {
        "sage_version": sage.__version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
    }


def _journal_run(spans: int, payload_bytes: int, durability: str | None, work: Path) -> dict[str, object]:
    """Record `spans` tool spans, each with a unique payload; time every span and the seal."""
    from sage import SageRecorder

    run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=str(work)))
    kwargs: dict[str, object] = {}
    if durability is not None:
        kwargs.update(journal_dir=run_dir / "journal", journal_durability=durability)
    rec = SageRecorder(
        title="journal-bench", trace_id=f"bench-{run_dir.name}", blob_store=run_dir / "blobs",
        register_trace=False, **kwargs,
    )
    filler = "p" * max(0, payload_bytes - 8)
    samples: list[float] = []
    started = time.perf_counter()
    rec.__enter__()
    for index in range(spans):
        payload = f"{index:08d}{filler}"
        t0 = time.perf_counter()
        with rec.tool_call("lookup", inputs={"query": payload}) as tool:
            tool.set_output(ok=True, rows=index)
        samples.append(time.perf_counter() - t0)
    recorded = time.perf_counter()
    rec.__exit__(None, None, None)
    sealed = time.perf_counter()
    bundle = rec.finalize()
    assert len(bundle.spans) == spans
    shutil.rmtree(run_dir, ignore_errors=True)
    return {
        "durability": durability or "none (in memory)",
        "payload_bytes": payload_bytes,
        "spans": spans,
        "per_span": _stats(samples),
        "seal_ms": round((sealed - recorded) * 1000, 3),
        "end_to_end_per_span_ms": round((sealed - started) / spans * 1000, 4),
    }


def journal_benchmark(args: argparse.Namespace) -> dict[str, object]:
    from sage.journal import (
        DEFAULT_BATCH_INTERVAL_MS,
        DEFAULT_BATCH_MAX_SPANS,
        DEFAULT_DURABILITY,
        MAX_UNCOMMITTED_BATCHES,
    )

    modes = list(DURABILITY_MODES) if args.durability == "all" else [args.durability or DEFAULT_DURABILITY]
    sizes = [int(part) for part in str(args.payload_bytes).split(",") if part.strip()]
    work = Path(tempfile.mkdtemp(prefix="sage-journal-bench-"))
    results: list[dict[str, object]] = []
    try:
        _journal_run(min(args.spans, 50), sizes[0], DEFAULT_DURABILITY, work)  # warm imports and caches
        for size in sizes:
            if not args.no_memory_baseline:
                results.append(_journal_run(args.spans, size, None, work))
            for mode in modes:
                # "span" pays four fsyncs per span; cap its span count so the sweep stays short.
                count = min(args.spans, args.span_mode_spans) if mode == "span" else args.spans
                results.append(_journal_run(count, size, mode, work))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return {
        "benchmark": "journal per-span cost",
        "workload": "tool spans with one unique payload each; unique payloads above 1 KiB write one blob per span",
        "note": NOTE,
        "default_durability": DEFAULT_DURABILITY,
        "batch_interval_ms": DEFAULT_BATCH_INTERVAL_MS,
        "batch_max_spans": DEFAULT_BATCH_MAX_SPANS,
        "max_uncommitted_spans": DEFAULT_BATCH_MAX_SPANS * MAX_UNCOMMITTED_BATCHES,
        **_environment(),
        "results": results,
    }


def _emit(report: dict[str, object], out: str | None) -> None:
    text = json.dumps(report, indent=2, sort_keys=True)
    if out:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(text + "\n", encoding="utf-8")
    print(text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", default="workflow", choices=["workflow", "journal"])
    parser.add_argument("--durability", default=None, choices=[*DURABILITY_MODES, "all"],
                        help="live-journal durability mode (default: the library default; 'all' sweeps every mode)")
    parser.add_argument("--out", default=None, help="also write the JSON report to this file")
    workflow = parser.add_argument_group("workflow mode")
    workflow.add_argument("--runs", type=int, default=100)
    workflow.add_argument("--warmup", type=int, default=10)
    workflow.add_argument("--scenario", default="success", choices=["success", "tool-error", "tool-timeout"])
    workflow.add_argument("--no-journal", action="store_true", help="record in memory only (isolates live-journal disk cost)")
    journal = parser.add_argument_group("journal mode")
    journal.add_argument("--spans", type=int, default=1000, help="spans per run")
    journal.add_argument("--span-mode-spans", type=int, default=300, help="span cap for the fsync-per-span mode")
    journal.add_argument("--payload-bytes", default="64,512,4096", help="comma-separated payload sizes to sweep")
    journal.add_argument("--no-memory-baseline", action="store_true", help="skip the in-memory (no journal) rows")
    journal.add_argument("--max-default-median-ms", type=float, default=None,
                         help="exit 1 if the default mode's per-span median exceeds this at any payload size")
    args = parser.parse_args(argv)

    if args.mode == "journal":
        report = journal_benchmark(args)
        _emit(report, args.out)
        if args.max_default_median_ms is not None:
            slow = [
                row for row in report["results"]  # type: ignore[union-attr]
                if row["durability"] == report["default_durability"]
                and row["per_span"]["median_ms"] > args.max_default_median_ms
            ]
            for row in slow:
                print(
                    f"FAIL: default mode median {row['per_span']['median_ms']} ms at "
                    f"{row['payload_bytes']} bytes exceeds {args.max_default_median_ms} ms",
                    file=sys.stderr,
                )
            return 1 if slow else 0
        return 0

    modes = list(DURABILITY_MODES) if args.durability == "all" else [args.durability]
    reports = [workflow_benchmark(args, mode) for mode in modes]
    _emit(reports[0] if len(reports) == 1 else {"note": NOTE, "runs": reports}, args.out)
    return 0


def workflow_benchmark(args: argparse.Namespace, durability: str | None) -> dict[str, object]:
    import langchain_core

    import consultancy_demo as demo
    import sage
    from sage import SageRecorder
    from sage.adapters.langchain_callback import SageLangChainCallback
    from sage.pack import pack_artifact
    from sage.verify import verify_artifact

    request = {"message": demo.SUPPORT_REQUEST}
    hmac_key = "overhead-measurement-key"

    def plain() -> None:
        workflow = demo._build_workflow(args.scenario, demo.SimulatedClock())
        try:
            workflow.invoke(request)
        except (demo.AccountServiceError, TimeoutError):
            pass

    work = Path(tempfile.mkdtemp(prefix="sage-overhead-"))
    last: dict[str, object] = {}
    resolved: dict[str, str] = {}

    def instrumented(index: int) -> tuple[float, float]:
        run_dir = work / f"r{index}"
        workflow = demo._build_workflow(args.scenario, demo.SimulatedClock())
        rec = SageRecorder(title="overhead", trace_id=f"overhead-{index}",
                           journal_dir=None if args.no_journal else run_dir / "journal",
                           journal_durability=durability,
                           blob_store=run_dir / "blobs")
        resolved["durability"] = rec.journal_durability
        t0 = time.perf_counter()
        with rec:
            handler = SageLangChainCallback(rec)
            try:
                workflow.invoke(request, config={"callbacks": [handler]})
            except (demo.AccountServiceError, TimeoutError):
                pass
            handler.assert_complete()
        t1 = time.perf_counter()
        source = run_dir / "journal"
        if args.no_journal:
            source = rec.export(run_dir / "bundle.sage.json")
        pack = pack_artifact(source, run_dir / "evidence.sage.tar.gz", blob_store=run_dir / "blobs",
                             hmac_key=hmac_key)
        verify_artifact(pack, hmac_key=hmac_key, check_witness=True, witness_key=hmac_key)
        t2 = time.perf_counter()
        bundle = rec.finalize()
        last.update(
            span_count=len(bundle.spans),
            recorded_input_bytes=sum(len(json.dumps(s.inputs)) for s in bundle.spans),
            pack_bytes=Path(pack).stat().st_size,
        )
        shutil.rmtree(run_dir, ignore_errors=True)
        return t1 - t0, t2 - t1

    for i in range(args.warmup):
        plain()
        instrumented(-1 - i)

    plain_s: list[float] = []
    rec_s: list[float] = []
    seal_s: list[float] = []
    for i in range(args.runs):
        t0 = time.perf_counter()
        plain()
        plain_s.append(time.perf_counter() - t0)
        recorded, sealed = instrumented(i)
        rec_s.append(recorded)
        seal_s.append(sealed)
    shutil.rmtree(work, ignore_errors=True)

    plain_stats = _stats(plain_s)
    rec_stats = _stats(rec_s)
    added_ms = round(rec_stats["median_ms"] - plain_stats["median_ms"], 3)
    span_count = int(last.get("span_count") or 0)
    report = {
        "workload": f"synthetic consultancy workflow, scenario={args.scenario}, deterministic test model",
        "live_journal": not args.no_journal,
        "journal_durability": None if args.no_journal else resolved.get("durability"),
        "note": NOTE,
        "sage_version": sage.__version__,
        "langchain_core": langchain_core.__version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "added_recording_per_span_median_ms": round(added_ms / span_count, 4) if span_count else None,
        "runs": args.runs,
        "warmup": args.warmup,
        "uninstrumented_workflow": plain_stats,
        "instrumented_workflow": rec_stats,
        "added_recording_median_ms": added_ms,
        "seal_pack_verify": _stats(seal_s),
        **last,
    }
    return report


if __name__ == "__main__":
    raise SystemExit(main())
