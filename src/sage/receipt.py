from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

from sage.errors import ChainIntegrityError
from sage.keys import resolve_key_material
from sage.schema import utc_now


def receipt_body_from_report(report: dict[str, Any]) -> dict[str, Any]:
    pack = report.get("pack") or {}
    wit = report.get("witness") or {}
    blobs = report.get("blobs") or {}
    policy = report.get("policy") or {}
    fingerprint = (
        pack.get("content_digest")
        or report.get("bundle_hash")
        or report.get("artifact_fingerprint")
    )
    return {
        "format": "sage.verify.receipt.v1",
        "artifact_fingerprint": fingerprint,
        "kind": report.get("kind"),
        "path_basename": Path(str(report.get("path") or "")).name,
        "bundle_id": report.get("bundle_id"),
        "bundle_hash": report.get("bundle_hash"),
        "blob_merkle": blobs.get("blob_merkle") or pack.get("blob_merkle"),
        "witness_tip": wit.get("tip_record_hash"),
        "pack_format": pack.get("format"),
        "policy_id": policy.get("policy_id"),
        "policy_digest": policy.get("policy_digest"),
        "sage_version": report.get("sage_version"),
        "verified_at": utc_now(),
        "ok": bool(report.get("ok")),
    }


def seal_receipt(
    body: dict[str, Any],
    *,
    hmac_key: bytes | str | None = None,
    key_id: str | None = None,
    key_ring: str | Path | dict | None = None,
) -> dict[str, Any]:
    key, kid = resolve_key_material(
        hmac_key=hmac_key,
        key_id=key_id,
        key_ring=key_ring,
        env_fallback=("SAGE_VERIFY_KEY", "SAGE_PACK_KEY"),
    )
    receipt = dict(body)
    if key is not None:
        payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        att: dict[str, Any] = {
            "alg": "hmac-sha256",
            "mac": hmac.new(key, payload, hashlib.sha256).hexdigest(),
        }
        if kid:
            att["key_id"] = kid
        receipt["attestation"] = att
    return receipt


def write_receipt(
    report: dict[str, Any],
    path: str | Path,
    *,
    hmac_key: bytes | str | None = None,
    key_id: str | None = None,
    key_ring: str | Path | dict | None = None,
) -> Path:
    body = receipt_body_from_report(report)
    receipt = seal_receipt(body, hmac_key=hmac_key, key_id=key_id, key_ring=key_ring)
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")
    return out


def verify_receipt(
    path: str | Path,
    *,
    hmac_key: bytes | str | None = None,
    key_id: str | None = None,
    key_ring: str | Path | dict | None = None,
    expect_fingerprint: str | None = None,
    allow_unsigned: bool = False,
) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    att = data.get("attestation") or {}
    body = {k: v for k, v in data.items() if k != "attestation"}
    kid = key_id or att.get("key_id")
    key, _ = resolve_key_material(
        hmac_key=hmac_key,
        key_id=kid,
        key_ring=key_ring,
        env_fallback=("SAGE_VERIFY_KEY", "SAGE_PACK_KEY"),
    )
    if key is None and att.get("mac"):
        key, _ = resolve_key_material(env_fallback=("SAGE_VERIFY_KEY", "SAGE_PACK_KEY"))
    if not att.get("mac"):
        if not allow_unsigned:
            raise ChainIntegrityError("receipt missing HMAC attestation (refuse unsigned)")
    else:
        if key is None:
            raise ChainIntegrityError("receipt has MAC but no verify key available")
        payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(att["mac"]), expected):
            raise ChainIntegrityError("receipt MAC mismatch")
    if expect_fingerprint and body.get("artifact_fingerprint") != expect_fingerprint:
        raise ChainIntegrityError(
            f"receipt fingerprint mismatch: claimed={body.get('artifact_fingerprint')!r} "
            f"expected={expect_fingerprint!r}"
        )
    if not body.get("ok"):
        raise ChainIntegrityError("receipt records failed verification")
    return {"ok": True, "receipt": body, "key_id": att.get("key_id"), "mac_verified": bool(att.get("mac"))}
