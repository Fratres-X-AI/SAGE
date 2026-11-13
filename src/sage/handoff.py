from __future__ import annotations

import copy
import json
import os
import shutil
import uuid
from pathlib import Path
from typing import Any

from sage.errors import SageError
from sage.pack import pack_artifact
from sage.policy import VerifyPolicy, load_policy
from sage.receipt import write_receipt
from sage.verify import verify_artifact


class HandoffSetupError(SageError):
    """Handoff cannot be built as requested (missing key material, existing kit, bad input)."""


HANDOFF_MD = """# SAGE Evidence Handoff

This directory is an offline-verifiable incident evidence kit.

## Contents

- `evidence.sage.tar.gz`: sealed pack (journal, content-addressed blobs, pack.json, witness log)
- `policy.json`: the verification policy the producer applied when building this kit
- `verify.receipt.json`: verification receipt bound to this pack and policy
- `verify_handoff.py`: recipient re-verification helper

Any other file a producer adds (for example `INCIDENT_SUMMARY.md` or `build_record.json`) is a
convenience note, not evidence. Only the pack, verified as below, is evidence.

## What the recipient needs (provisioned separately, never inside this kit)

- The SAGE wheel (`sage_incident_bundles-<version>-py3-none-any.whl`) and Python 3.10 or newer.
- The HMAC verification key (for example a file `hmac.key`), if `policy.json` sets
  `require_pack_hmac` or `require_witness_hmac`.
- The producer's Ed25519 public key (for example a file `ed25519.public.txt`), if `policy.json`
  sets `require_pack_signature`. Obtain it and its SHA-256 fingerprint through a separate trusted
  channel. A public key embedded in the pack does not establish the producer's identity by itself.

HMAC and signatures prove different things: anyone holding the shared HMAC key can produce a valid
HMAC, while only the holder of the signing private key can produce a valid signature.

## Verify

1. Create a virtual environment and install the wheel. If `policy.json` sets
   `require_pack_signature`, install the `[sign]` extra (adds the `cryptography` package);
   otherwise the plain wheel is enough.

   ```bash
   python -m venv sage-venv                        # Windows: py -3.12 -m venv sage-venv
   . sage-venv/bin/activate                        # PowerShell: sage-venv\\Scripts\\Activate.ps1
   python -m pip install "sage_incident_bundles-<version>-py3-none-any.whl[sign]"
   ```

   In the commands below, `<keys>` is wherever you saved the key files you received separately
   (they are not in this directory). Run the commands from inside this directory.

2. Set the HMAC key to the contents of the key file (not its path):

   ```bash
   export SAGE_PACK_KEY="$(cat <keys>/hmac.key)"                       # bash
   $env:SAGE_PACK_KEY = (Get-Content -Raw <keys>\\hmac.key).Trim()      # PowerShell
   ```

3. Run the helper. Pass the contents of the public key file with the `--public-key=` form
   (keys can start with `-`):

   ```bash
   python verify_handoff.py --public-key="$(cat <keys>/ed25519.public.txt)"                       # bash
   python verify_handoff.py --public-key="$((Get-Content -Raw <keys>\\ed25519.public.txt).Trim())"  # PowerShell
   ```

4. Compare `pinned_key_fingerprint` in the output with the fingerprint you received out of band.
   It is the SHA-256 of the raw 32-byte key (the urlsafe-base64-decoded file contents). To compute
   it independently of the helper:

   ```bash
   python -c "import base64,hashlib,sys; k=open(sys.argv[1]).read().strip(); print(hashlib.sha256(base64.urlsafe_b64decode(k + '=' * (-len(k) % 4))).hexdigest())" <keys>/ed25519.public.txt
   ```

Exit codes: `0` evidence, policy, and receipt all verified; `1` integrity, policy, or receipt
failure (the evidence or kit does not match); `2` setup problem (SAGE or `cryptography` not
installed, required key not provided, kit file missing).
"""


VERIFY_SCRIPT = '''#!/usr/bin/env python3
"""Recipient re-verification of a SAGE handoff kit. Exit 0 ok, 1 integrity/policy, 2 setup."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _fingerprint(pin: str | None) -> str | None:
    if not pin:
        return None
    try:
        return hashlib.sha256(base64.urlsafe_b64decode(pin + "=" * (-len(pin) % 4))).hexdigest()
    except ValueError:
        return None


def _out(payload: dict, code: int) -> int:
    print(json.dumps(payload, indent=2, sort_keys=True), file=sys.stdout if code == 0 else sys.stderr)
    return code


def _short(exc: BaseException) -> str:
    return str(exc).splitlines()[0][:300] if str(exc) else type(exc).__name__


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-key", default=None, help="pinned Ed25519 public key; use --public-key=<base64> (keys may start with -) or SAGE_SIGN_PUBLIC_KEY")
    args = parser.parse_args(argv)
    try:
        from sage.errors import BlobIntegrityError, ChainIntegrityError, SageError
        from sage.policy import load_policy
        from sage.receipt import verify_receipt
        from sage.verify import verify_artifact
    except ImportError:
        return _out({"ok": False, "stage": "setup", "error": "SAGE is not installed in this Python environment"}, 2)

    pack = ROOT / "evidence.sage.tar.gz"
    receipt = ROOT / "verify.receipt.json"
    policy_path = ROOT / "policy.json"
    for required in (pack, policy_path):
        if not required.exists():
            return _out({"ok": False, "stage": "setup", "error": f"kit file missing: {required.name}"}, 2)
    if not receipt.exists():
        return _out({"ok": False, "stage": "receipt", "error": "verify.receipt.json missing: kit is incomplete"}, 1)

    try:
        policy = load_policy(policy_path)
    except SageError as exc:
        return _out({"ok": False, "stage": "policy", "error": _short(exc)}, 1)

    key = os.environ.get("SAGE_PACK_KEY") or os.environ.get("SAGE_HANDOFF_KEY")
    receipt_key = os.environ.get("SAGE_VERIFY_KEY") or key
    pin = args.public_key or os.environ.get("SAGE_SIGN_PUBLIC_KEY")
    if (policy.require_pack_hmac or policy.require_witness_hmac) and not key:
        return _out({"ok": False, "stage": "setup", "error": "policy requires HMAC: set SAGE_PACK_KEY"}, 2)
    if policy.require_pack_signature and not pin:
        return _out({"ok": False, "stage": "setup", "error": "policy requires a pinned public key: pass --public-key=<base64> or set SAGE_SIGN_PUBLIC_KEY"}, 2)
    if policy.require_pack_signature:
        from sage.signing import signing_available

        if not signing_available():
            return _out({"ok": False, "stage": "setup", "error": "policy requires Ed25519 signatures but the 'cryptography' package is not installed: python -m pip install \\"<wheel file>[sign]\\" (or: python -m pip install cryptography)"}, 2)
    pin_fp = _fingerprint(pin)

    try:
        report = verify_artifact(pack, policy=policy, hmac_key=key, witness_key=key, public_key=pin)
    except (ChainIntegrityError, BlobIntegrityError) as exc:
        return _out({"ok": False, "stage": "evidence", "error_type": type(exc).__name__, "error": _short(exc), "pinned_key_fingerprint": pin_fp}, 1)
    except SageError as exc:
        return _out({"ok": False, "stage": "evidence", "error_type": type(exc).__name__, "error": _short(exc)}, 2)

    fingerprint = (report.get("pack") or {}).get("content_digest") or report.get("bundle_hash")
    try:
        bound = verify_receipt(
            receipt,
            hmac_key=receipt_key,
            expect_fingerprint=fingerprint,
            allow_unsigned=not (policy.require_pack_hmac or policy.require_witness_hmac),
        )
    except ChainIntegrityError as exc:
        return _out({"ok": False, "stage": "receipt", "error": _short(exc)}, 1)
    body = bound["receipt"]
    fresh_policy = report.get("policy") or {}
    mismatches = [
        name
        for name, claimed, actual in (
            ("bundle_hash", body.get("bundle_hash"), report.get("bundle_hash")),
            ("bundle_id", body.get("bundle_id"), report.get("bundle_id")),
            ("policy_digest", body.get("policy_digest"), fresh_policy.get("policy_digest")),
        )
        if claimed != actual
    ]
    if mismatches:
        return _out({"ok": False, "stage": "receipt", "error": "receipt does not match this kit", "fields": mismatches}, 1)

    return _out(
        {
            "ok": True,
            "evidence_verified": True,
            "receipt_bound": True,
            "receipt_mac_verified": bound["mac_verified"],
            "signature_pinned": bool(report.get("pack_signature_pinned")),
            "pinned_key_fingerprint": pin_fp,
            "bundle_id": report.get("bundle_id"),
            "bundle_hash": report.get("bundle_hash"),
            "policy_id": fresh_policy.get("policy_id"),
            "policy_digest": fresh_policy.get("policy_digest"),
            "sage_version": report.get("sage_version"),
        },
        0,
    )


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _resolve_handoff_policy(
    policy: str | Path | dict[str, Any] | VerifyPolicy | None,
    *,
    hmac_key: bytes | str | None,
) -> VerifyPolicy:
    if policy is not None:
        if isinstance(policy, VerifyPolicy):
            return copy.deepcopy(policy)
        return load_policy(copy.deepcopy(policy) if isinstance(policy, dict) else policy)
    pol = VerifyPolicy(
        policy_id="handoff-default",
        require_witness=True,
        require_pack_v2=True,
        require_blob_inventory=True,
        forbid_live_journal=True,
    )
    if hmac_key:
        pol.require_witness_hmac = True
        pol.require_pack_hmac = True
    return pol


def create_handoff(
    path: str | Path,
    out_dir: str | Path,
    *,
    hmac_key: bytes | str | None = None,
    policy: str | Path | dict[str, Any] | VerifyPolicy | None = None,
    actor: str = "handoff",
    key_id: str | None = None,
    public_key: str | None = None,
    sign: bool | None = None,
    private_key: str | None = None,
    overwrite: bool = False,
) -> Path:
    """Build an offline evidence handoff directory from a bundle, journal, or pack.

    An explicit ``policy`` is enforced as given; it is never weakened to fit missing keys.
    The kit is assembled in a staging directory and promoted only after verification and
    receipt generation succeed.
    """
    dest = Path(out_dir)
    if dest.exists() and any(dest.iterdir()):
        if not overwrite:
            raise HandoffSetupError(f"handoff destination is not empty: {dest} (pass overwrite=True)")
    pol = _resolve_handoff_policy(policy, hmac_key=hmac_key)
    if (pol.require_pack_hmac or pol.require_witness_hmac) and not hmac_key:
        raise HandoffSetupError(f"policy {pol.policy_id!r} requires HMAC but no hmac_key was supplied")
    if pol.require_pack_signature:
        from sage.signing import resolve_pinned_public_key

        if not resolve_pinned_public_key(public_key=public_key, key_id=key_id):
            raise HandoffSetupError(
                f"policy {pol.policy_id!r} requires a pinned Ed25519 public key; the embedded key is not accepted"
            )

    src = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    staging = dest.parent / f".{dest.name}.staging-{uuid.uuid4().hex[:12]}"
    staging.mkdir()
    try:
        pack_path = staging / "evidence.sage.tar.gz"
        if src.name.endswith(".tar.gz"):
            shutil.copy2(src, pack_path)
        else:
            want_sign = sign if sign is not None else (pol.require_pack_signature or None)
            pack_artifact(
                src,
                pack_path,
                hmac_key=hmac_key,
                actor=actor,
                write_witness=True,
                pack_version=2,
                key_id=key_id,
                sign=want_sign,
                private_key=private_key,
            )
        (staging / "policy.json").write_text(
            json.dumps(pol.to_dict(), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        report = verify_artifact(
            pack_path,
            policy=pol,
            hmac_key=hmac_key,
            witness_key=hmac_key,
            public_key=public_key,
            key_id=key_id,
        )
        write_receipt(report, staging / "verify.receipt.json", hmac_key=hmac_key, key_id=key_id)
        (staging / "HANDOFF.md").write_text(HANDOFF_MD, encoding="utf-8")
        (staging / "verify_handoff.py").write_text(VERIFY_SCRIPT, encoding="utf-8")

        if dest.exists():
            shutil.rmtree(dest)
        os.replace(staging, dest)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return dest
