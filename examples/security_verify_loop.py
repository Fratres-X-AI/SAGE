#!/usr/bin/env python3
"""Golden security-tool loop: record → pack v2 → strict verify → handoff."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from sage import SageRecorder
from sage.handoff import create_handoff
from sage.policy import load_policy
from sage.verify import verify_artifact

ROOT = Path(__file__).resolve().parents[1]
STRICT = ROOT / "policies" / "strict.json"
KEY = os.environ.get("SAGE_PACK_KEY", "demo-only-not-for-production")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="sage-sec-") as tmp:
        tmp_path = Path(tmp)
        blobs = tmp_path / "blobs"
        with SageRecorder(
            "security-loop",
            blob_store=blobs,
            journal_dir=tmp_path / "live",
            register_trace=False,
        ) as rec:
            with rec.tool_call(
                "fetch",
                inputs={"api_key": "sk-demo-secret-value", "body": "X" * 2048},
            ) as tool:
                tool.set_output(ok=True)
            path = rec.export(tmp_path / "incident.sage.json")

        kit = create_handoff(path, tmp_path / "kit", hmac_key=KEY, actor="example")
        report = verify_artifact(
            kit / "evidence.sage.tar.gz",
            hmac_key=KEY,
            check_witness=True,
            witness_key=KEY,
            policy=load_policy(STRICT),
        )
        assert report["ok"]
        print("ok", report["bundle_hash"], "pack", report["pack"]["format"])


if __name__ == "__main__":
    main()
