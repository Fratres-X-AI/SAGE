from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

from sage.errors import ChainIntegrityError
from sage.journal import append_jsonl_line, load_jsonl_objects
from sage.schema import utc_now

WITNESS_JSONL = "witness.jsonl"
ZERO_HASH = "0" * 64


def _key_bytes(key: bytes | str | None) -> bytes | None:
    if key is None:
        env = os.environ.get("SAGE_WITNESS_KEY") or os.environ.get("SAGE_PACK_KEY")
        if not env:
            return None
        return env.encode("utf-8")
    return key.encode("utf-8") if isinstance(key, str) else key


def witness_mac(record_body: dict[str, Any], key: bytes | str) -> str:
    payload = json.dumps(record_body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    raw = key.encode("utf-8") if isinstance(key, str) else key
    return hmac.new(raw, payload, hashlib.sha256).hexdigest()


def append_witness(
    directory: str | Path,
    *,
    action: str,
    bundle_hash: str,
    chain_tip: str | None = None,
    actor: str = "local",
    hmac_key: bytes | str | None = None,
    key_id: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Append a custody witness record beside a journal/evidence directory."""
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    path = root / WITNESS_JSONL
    prev = ZERO_HASH
    if path.exists():
        objects, _ = load_jsonl_objects(path)
        if objects:
            prev = str(objects[-1].get("record_hash") or ZERO_HASH)
    body: dict[str, Any] = {
        "ts": utc_now(),
        "action": action,
        "bundle_hash": bundle_hash,
        "chain_tip": chain_tip or "",
        "actor": actor,
        "prev_hash": prev,
    }
    if extra:
        body["extra"] = extra
    key = _key_bytes(hmac_key)
    if key is not None:
        att: dict[str, Any] = {"alg": "hmac-sha256", "mac": witness_mac(body, key)}
        if key_id:
            att["key_id"] = key_id
        body["attestation"] = att
    record = dict(body)
    record["record_hash"] = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    append_jsonl_line(path, record)
    return record


def verify_witness_log(
    directory: str | Path,
    *,
    hmac_key: bytes | str | None = None,
    expect_bundle_hash: str | None = None,
    expect_chain_tip: str | None = None,
    require_hmac: bool = False,
) -> dict[str, Any]:
    """Fail-closed verification of append-only witness.jsonl custody chain."""
    root = Path(directory)
    path = root / WITNESS_JSONL
    if not path.exists():
        raise ChainIntegrityError(f"missing {WITNESS_JSONL} under {root}")
    objects, rejected = load_jsonl_objects(path)
    if rejected:
        raise ChainIntegrityError(f"witness log torn tail ({rejected} bytes)")
    if not objects:
        raise ChainIntegrityError("witness log empty")
    key = _key_bytes(hmac_key)
    if require_hmac and key is None:
        raise ChainIntegrityError("witness HMAC required but no key available")
    prev = ZERO_HASH
    hmac_verified = False
    for i, rec in enumerate(objects):
        claimed_hash = rec.get("record_hash")
        body = {k: v for k, v in rec.items() if k != "record_hash"}
        expected_hash = hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if claimed_hash != expected_hash:
            raise ChainIntegrityError(f"witness record_hash mismatch at index={i}")
        if body.get("prev_hash") != prev:
            raise ChainIntegrityError(
                f"witness prev_hash break at index={i}: claimed={body.get('prev_hash')!r} expected={prev!r}"
            )
        att = body.get("attestation") or {}
        if key is not None or require_hmac:
            unsigned = {k: v for k, v in body.items() if k != "attestation"}
            if not att or att.get("alg") != "hmac-sha256":
                raise ChainIntegrityError(f"witness missing HMAC at index={i}")
            if key is None:
                raise ChainIntegrityError("witness HMAC required but no key available")
            expected_mac = witness_mac(unsigned, key)
            if not hmac.compare_digest(str(att.get("mac") or ""), expected_mac):
                raise ChainIntegrityError(f"witness HMAC mismatch at index={i}")
            hmac_verified = True
        prev = str(claimed_hash)
    tip = objects[-1]
    if expect_bundle_hash and tip.get("bundle_hash") != expect_bundle_hash:
        raise ChainIntegrityError(
            f"witness tip bundle_hash mismatch: claimed={tip.get('bundle_hash')!r} "
            f"expected={expect_bundle_hash!r}"
        )
    if expect_chain_tip is not None:
        claimed_tip = str(tip.get("chain_tip") or "")
        if claimed_tip and claimed_tip != expect_chain_tip:
            raise ChainIntegrityError(
                f"witness tip chain_tip mismatch: claimed={claimed_tip!r} expected={expect_chain_tip!r}"
            )
    return {
        "ok": True,
        "records": len(objects),
        "tip_action": tip.get("action"),
        "tip_bundle_hash": tip.get("bundle_hash"),
        "tip_chain_tip": tip.get("chain_tip"),
        "tip_record_hash": tip.get("record_hash"),
        "hmac_verified": hmac_verified,
    }
