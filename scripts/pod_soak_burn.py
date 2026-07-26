#!/usr/bin/env python3
"""Extra process-pool custody burn to saturate cgroup CPUs during soak."""
from __future__ import annotations

import json
import os
import shutil
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path


def _cgroup_cpus() -> int:
    path = Path("/sys/fs/cgroup/cpu.max")
    if path.is_file():
        quota, period = path.read_text(encoding="utf-8").split()
        if quota != "max":
            return max(1, int(float(quota) / float(period)))
    return 8


def _one(job: tuple[int, str, str]) -> dict:
    idx, root_s, key = job
    from sage.recorder import SageRecorder
    from sage.pack import pack_artifact, unpack_artifact
    from sage.verify import verify_artifact

    root = Path(root_s) / f"w{idx}"
    if root.exists():
        shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True)
    with SageRecorder(f"burn-{idx}", blob_store=root / "b", register_trace=False) as rec:
        with rec.agent_step("boss", inputs={"api_key": "sk-burn", "goal": f"g{idx}"}):
            for j in range(12):
                with rec.tool_call(f"t{j}", inputs={"body": ("B" * 1800), "j": j, "api_key": "sk-burn"}):
                    pass
        path = rec.export(root / "i.sage.json")
    pack = pack_artifact(path, root / "p.sage.tar.gz", hmac_key=key)
    report = verify_artifact(pack, hmac_key=key, check_witness=True, witness_key=key)
    assert report["ok"]
    unpack_artifact(pack, root / "out", hmac_key=key, quarantine=True)
    shutil.rmtree(root, ignore_errors=True)
    return {"idx": idx, "ok": True, "bundle_hash": report.get("bundle_hash")}


def main() -> int:
    minutes = int(os.environ.get("SOAK_MINUTES", "45"))
    cpus = _cgroup_cpus()
    # Leave room for the main soak's 8 lanes; still fill the quota hard.
    workers = int(os.environ.get("SOAK_BURN_WORKERS", str(max(8, cpus - 8))))
    deadline = time.time() + minutes * 60
    log_dir = Path(os.environ.get("SOAK_LOG_DIR", "/workspace/sage_soak_logs"))
    log_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    summary = log_dir / f"soak_burn_{stamp}.jsonl"
    work = Path(f"/tmp/sage_soak_burn_{stamp}")
    work.mkdir(parents=True, exist_ok=True)
    key = "soak-burn-hmac"
    round_i = 0
    ok = 0
    fail = 0
    print(f"burn start cgroup={cpus} workers={workers} minutes={minutes} work={work}", flush=True)
    while time.time() < deadline:
        round_i += 1
        t0 = time.time()
        jobs = [(i, str(work), key) for i in range(workers)]
        try:
            with ProcessPoolExecutor(max_workers=workers) as pool:
                results = [f.result() for f in as_completed([pool.submit(_one, j) for j in jobs])]
            assert all(r["ok"] for r in results)
            ok += 1
            line = {"round": round_i, "ok": True, "seconds": round(time.time() - t0, 3), "workers": workers}
        except Exception as exc:  # noqa: BLE001
            fail += 1
            line = {
                "round": round_i,
                "ok": False,
                "error": str(exc)[:200],
                "seconds": round(time.time() - t0, 3),
                "workers": workers,
            }
        with summary.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(line) + "\n")
        print(json.dumps(line), flush=True)
    print(f"burn done ok={ok} fail={fail}", flush=True)
    shutil.rmtree(work, ignore_errors=True)
    return 0 if ok and fail == 0 else (0 if ok else 1)


if __name__ == "__main__":
    raise SystemExit(main())
