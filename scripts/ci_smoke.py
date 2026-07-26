#!/usr/bin/env python3
"""Cross-platform CI smoke: handoff + strict policy + receipt."""

from __future__ import annotations

from pathlib import Path

from sage.handoff import create_handoff
from sage.policy import load_policy
from sage.receipt import verify_receipt
from sage.recorder import SageRecorder
from sage.verify import verify_artifact

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    root = Path("ci-v2")
    with SageRecorder("ci", blob_store=root / "blobs", register_trace=False) as rec:
        with rec.tool_call("t", inputs={"api_key": "sk-testkey1", "body": "B" * 2048}):
            pass
        path = rec.export(root / "inc.sage.json")
    kit = create_handoff(path, root / "kit", hmac_key="ci-key", actor="gha")
    report = verify_artifact(
        kit / "evidence.sage.tar.gz",
        hmac_key="ci-key",
        check_witness=True,
        witness_key="ci-key",
        policy=load_policy(ROOT / "policies" / "strict.json"),
    )
    assert report["ok"] and report["pack"]["format"] == "sage.pack.v2"
    verify_receipt(kit / "verify.receipt.json", hmac_key="ci-key")
    print(report["bundle_hash"])


if __name__ == "__main__":
    main()
