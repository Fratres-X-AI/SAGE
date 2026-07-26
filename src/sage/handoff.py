from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from sage.pack import pack_artifact
from sage.policy import VerifyPolicy, load_policy
from sage.receipt import write_receipt
from sage.verify import verify_artifact


HANDOFF_MD = """# SAGE Evidence Handoff

This directory is a portable, offline-verifiable incident evidence kit.

## Contents

- `evidence.sage.tar.gz` — sealed pack (journal + CAS blobs + pack.json + witness)
- `policy.json` — verification policy applied at handoff
- `verify.receipt.json` — HMAC-sealed verification transcript (if keys available)
- `verify_handoff.py` — stdlib re-verify helper

## Verify (auditor)

```bash
pip install sage-incident-bundles   # or use a checkout with PYTHONPATH=src
python verify_handoff.py
# or:
sage verify evidence.sage.tar.gz --policy policy.json --witness --hmac-key "$SAGE_PACK_KEY"
sage verify-receipt verify.receipt.json
```

Fail-closed: any integrity / policy failure exits non-zero.
"""


VERIFY_SCRIPT = '''#!/usr/bin/env python3
"""Offline re-verify of a SAGE handoff kit (stdlib + installed sage)."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main() -> int:
    try:
        from sage.verify import verify_artifact
        from sage.policy import load_policy, apply_policy
        from sage.receipt import verify_receipt
    except ImportError:
        print("sage not installed; pip install -e . from the SAGE checkout", file=sys.stderr)
        return 2

    pack = ROOT / "evidence.sage.tar.gz"
    policy = load_policy(ROOT / "policy.json")
    key = os.environ.get("SAGE_PACK_KEY") or os.environ.get("SAGE_HANDOFF_KEY")
    report = verify_artifact(
        pack,
        require_sealed=policy.require_sealed,
        hmac_key=key,
        check_blobs=policy.require_blob_inventory,
        check_witness=policy.require_witness or policy.require_witness_hmac,
        witness_key=key,
    )
    apply_policy(report, policy)
    receipt = ROOT / "verify.receipt.json"
    if receipt.exists():
        verify_receipt(receipt, hmac_key=os.environ.get("SAGE_VERIFY_KEY") or key)
    print(json.dumps({"ok": True, "bundle_hash": report.get("bundle_hash")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def create_handoff(
    path: str | Path,
    out_dir: str | Path,
    *,
    hmac_key: bytes | str | None = None,
    policy: str | Path | dict[str, Any] | VerifyPolicy | None = None,
    actor: str = "handoff",
    key_id: str | None = None,
) -> Path:
    """Build an offline evidence handoff directory from a bundle/journal/pack."""
    dest = Path(out_dir)
    dest.mkdir(parents=True, exist_ok=True)
    pol = policy if isinstance(policy, VerifyPolicy) else load_policy(policy)
    # Strengthen handoff defaults for auditor export.
    if policy is None:
        pol.require_witness = True
        pol.require_witness_hmac = bool(hmac_key)
        pol.require_pack_hmac = bool(hmac_key)
        pol.require_pack_v2 = True
        pol.require_blob_inventory = True
        pol.forbid_live_journal = True
        pol.policy_id = "handoff-default"

    src = Path(path)
    pack_path = dest / "evidence.sage.tar.gz"
    if src.name.endswith(".tar.gz"):
        shutil.copy2(src, pack_path)
    else:
        pack_artifact(
            src,
            pack_path,
            hmac_key=hmac_key,
            actor=actor,
            write_witness=True,
            pack_version=2,
            key_id=key_id,
        )

    (dest / "policy.json").write_text(
        json.dumps(pol.to_dict(), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (dest / "HANDOFF.md").write_text(HANDOFF_MD, encoding="utf-8")
    (dest / "verify_handoff.py").write_text(VERIFY_SCRIPT, encoding="utf-8")

    report = verify_artifact(
        pack_path,
        require_sealed=pol.require_sealed,
        hmac_key=hmac_key,
        check_blobs=pol.require_blob_inventory,
        check_witness=pol.require_witness or pol.require_witness_hmac,
        witness_key=hmac_key,
    )
    if hmac_key:
        report["pack_hmac_verified"] = True
    from sage.policy import apply_policy

    # For handoff creation, soften require_witness_hmac if no key (still require witness file).
    if not hmac_key:
        pol.require_witness_hmac = False
        pol.require_pack_hmac = False
    apply_policy(report, pol)
    write_receipt(report, dest / "verify.receipt.json", hmac_key=hmac_key, key_id=key_id)
    return dest
