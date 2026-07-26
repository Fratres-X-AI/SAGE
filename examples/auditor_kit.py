#!/usr/bin/env python3
"""Auditor kit: HMAC pack v2 + pinned Ed25519 + auditor policy + receipt.

Demonstrates the strongest in-repo verify posture (no external KMS required).
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from sage.handoff import create_handoff
from sage.keys import write_key_ring
from sage.pack import pack_artifact
from sage.policy import load_policy
from sage.receipt import verify_receipt
from sage.recorder import SageRecorder
from sage.signing import generate_keypair, signing_available
from sage.verify import verify_artifact

ROOT = Path(__file__).resolve().parents[1]
AUDITOR = ROOT / "policies" / "auditor.json"


def main() -> None:
    if not signing_available():
        raise SystemExit("need: pip install -e '.[sign]'")

    key = os.environ.get("SAGE_PACK_KEY", "auditor-demo-hmac-not-for-prod")
    kp = generate_keypair()

    with tempfile.TemporaryDirectory(prefix="sage-auditor-") as tmp:
        root = Path(tmp)
        ring_path = root / "keys.json"
        write_key_ring(
            ring_path,
            {
                "pack": {"env": "SAGE_PACK_KEY"},
                "sign": {"alg": "ed25519", "public_key": kp["public_key"]},
            },
        )
        os.environ["SAGE_PACK_KEY"] = key
        os.environ["SAGE_SIGN_PRIVATE_KEY"] = kp["private_key"]
        os.environ["SAGE_SIGN_PUBLIC_KEY"] = kp["public_key"]

        with SageRecorder("auditor", blob_store=root / "b", register_trace=False) as rec:
            with rec.tool_call(
                "tool",
                inputs={"api_key": "sk-auditor-secret", "body": "payload-" + ("Z" * 2000)},
            ):
                pass
            incident = rec.export(root / "incident.sage.json")

        pack = pack_artifact(
            incident,
            root / "evidence.sage.tar.gz",
            hmac_key=key,
            sign=True,
            key_id="sign",
        )
        report = verify_artifact(
            pack,
            hmac_key=key,
            check_witness=True,
            witness_key=key,
            require_signature=True,
            public_key=kp["public_key"],
            key_ring=ring_path,
            key_id="sign",
            policy=load_policy(AUDITOR),
        )
        assert report["ok"] and report.get("pack_signature_pinned")

        kit = create_handoff(incident, root / "kit", hmac_key=key, actor="auditor-kit")
        # Re-pack signed evidence into kit manually for demo clarity.
        signed_kit_pack = pack_artifact(
            incident,
            kit / "evidence.signed.sage.tar.gz",
            hmac_key=key,
            sign=True,
            key_id="sign",
        )
        verify_receipt(kit / "verify.receipt.json", hmac_key=key)

        out = {
            "ok": True,
            "bundle_hash": report["bundle_hash"],
            "pack": str(pack),
            "signed_kit_pack": str(signed_kit_pack),
            "policy": "auditor",
            "pinned": True,
        }
        print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
