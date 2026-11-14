#!/usr/bin/env python3
"""Recipient re-verification of a SAGE handoff kit. Exit 0 ok, 1 integrity/policy/receipt, 2 setup.

The same code runs as verify_handoff.py inside every kit, as `sage handoff verify <kit>`,
and as the single-file verifier sage-verify-<version>.pyz from the release.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path

KIT_DIR = Path(__file__).resolve().parent


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


def _read_key_file(path: str) -> str:
    text = Path(path).read_text(encoding="utf-8").strip()
    if not text:
        raise ValueError(f"key file is empty: {path}")
    return text


def _sign_hint() -> str:
    try:
        from sage.signing import install_hint

        return install_hint()
    except ImportError:
        return "python -m pip install cryptography"


def main(argv: list[str] | None = None, *, kit_required: bool = False) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("kit", nargs=None if kit_required else "?", default=None,
                        help="kit directory" if kit_required
                        else "kit directory (default: the directory holding this script)")
    parser.add_argument("--hmac-key-file", default=None, help="file holding the HMAC key (else SAGE_PACK_KEY)")
    parser.add_argument("--public-key-file", default=None,
                        help="file holding the pinned Ed25519 public key (else --public-key / SAGE_SIGN_PUBLIC_KEY)")
    parser.add_argument("--public-key", default=None,
                        help="pinned Ed25519 public key; use --public-key=<base64> (keys may start with -)")
    args = parser.parse_args(argv)
    root = Path(args.kit).resolve() if args.kit else KIT_DIR
    try:
        from sage.errors import BlobIntegrityError, ChainIntegrityError, SageError
        from sage.policy import load_policy
        from sage.receipt import verify_receipt
        from sage.verify import verify_artifact
    except ImportError:
        return _out({"ok": False, "stage": "setup", "error": "SAGE is not installed in this Python environment"}, 2)

    pack = root / "evidence.sage.tar.gz"
    receipt = root / "verify.receipt.json"
    policy_path = root / "policy.json"
    if not root.is_dir():
        return _out({"ok": False, "stage": "setup", "error": f"kit directory not found: {root}"}, 2)
    for required in (pack, policy_path):
        if not required.exists():
            return _out({"ok": False, "stage": "setup", "error": f"kit file missing: {required.name}"}, 2)
    if not receipt.exists():
        return _out({"ok": False, "stage": "receipt", "error_type": "ReceiptMismatchError",
                     "error": "verify.receipt.json missing: kit is incomplete"}, 1)

    try:
        key = _read_key_file(args.hmac_key_file) if args.hmac_key_file else None
        pin = _read_key_file(args.public_key_file) if args.public_key_file else None
    except (OSError, ValueError) as exc:
        return _out({"ok": False, "stage": "setup", "error": f"cannot read key file: {_short(exc)}"}, 2)

    try:
        policy = load_policy(policy_path)
    except SageError as exc:
        return _out({"ok": False, "stage": "policy", "error_type": type(exc).__name__, "error": _short(exc)}, 1)

    key = key or os.environ.get("SAGE_PACK_KEY") or os.environ.get("SAGE_HANDOFF_KEY")
    receipt_key = os.environ.get("SAGE_VERIFY_KEY") or key
    pin = pin or args.public_key or os.environ.get("SAGE_SIGN_PUBLIC_KEY")
    if (policy.require_pack_hmac or policy.require_witness_hmac) and not key:
        return _out({"ok": False, "stage": "setup",
                     "error": "policy requires HMAC: pass --hmac-key-file <file> or set SAGE_PACK_KEY"}, 2)
    if policy.require_pack_signature and not pin:
        return _out({"ok": False, "stage": "setup", "error": "policy requires a pinned public key: pass "
                     "--public-key-file <file>, --public-key=<base64>, or set SAGE_SIGN_PUBLIC_KEY"}, 2)
    if policy.require_pack_signature:
        try:
            from sage.signing import verification_available as _can_verify
        except ImportError:
            from sage.signing import signing_available as _can_verify
        if not _can_verify():
            return _out({"ok": False, "stage": "setup", "error": _sign_hint()}, 2)
    pin_fp = _fingerprint(pin)

    try:
        report = verify_artifact(pack, policy=policy, hmac_key=key, witness_key=key, public_key=pin)
    except (ChainIntegrityError, BlobIntegrityError) as exc:
        return _out({"ok": False, "stage": "evidence", "error_type": type(exc).__name__, "error": _short(exc),
                     "pinned_key_fingerprint": pin_fp}, 1)
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
        return _out({"ok": False, "stage": "receipt", "error_type": "ReceiptMismatchError", "error": _short(exc)}, 1)
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
        return _out({"ok": False, "stage": "receipt", "error_type": "ReceiptMismatchError",
                     "error": "receipt does not match this kit", "fields": mismatches}, 1)

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
