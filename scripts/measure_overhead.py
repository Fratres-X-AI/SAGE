#!/usr/bin/env python3
"""Measure SAGE overhead on the synthetic consultancy workflow (local measurement, not an SLA).

    python scripts/measure_overhead.py --runs 100 --warmup 10 --out overhead.json

Reports median and p95 for: the uninstrumented workflow, the same workflow recorded through the
LangChain callback (live journal on), and, separately, seal + pack + verify time. Also reports span
count, recorded input size, and pack size.
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--runs", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--scenario", default="success", choices=["success", "tool-error", "tool-timeout"])
    parser.add_argument("--out", default=None)
    parser.add_argument("--no-journal", action="store_true", help="record in memory only (isolates live-journal disk cost)")
    args = parser.parse_args(argv)

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

    def instrumented(index: int) -> tuple[float, float]:
        run_dir = work / f"r{index}"
        workflow = demo._build_workflow(args.scenario, demo.SimulatedClock())
        rec = SageRecorder(title="overhead", trace_id=f"overhead-{index}",
                           journal_dir=None if args.no_journal else run_dir / "journal",
                           blob_store=run_dir / "blobs")
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
    report = {
        "workload": f"synthetic consultancy workflow, scenario={args.scenario}, deterministic test model",
        "live_journal": not args.no_journal,
        "note": "Local measurement on the documented synthetic workload. Not a production SLA.",
        "sage_version": sage.__version__,
        "langchain_core": langchain_core.__version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "runs": args.runs,
        "warmup": args.warmup,
        "uninstrumented_workflow": plain_stats,
        "instrumented_workflow": rec_stats,
        "added_recording_median_ms": round(rec_stats["median_ms"] - plain_stats["median_ms"], 3),
        "seal_pack_verify": _stats(seal_s),
        **last,
    }
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
