from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from sage.errors import ChainIntegrityError


def resolve_key_material(
    *,
    hmac_key: bytes | str | None = None,
    key_id: str | None = None,
    key_ring: str | Path | dict[str, Any] | None = None,
    env_fallback: tuple[str, ...] = ("SAGE_PACK_KEY", "SAGE_WITNESS_KEY", "SAGE_VERIFY_KEY"),
) -> tuple[bytes | None, str | None]:
    """Resolve (key_bytes, key_id). Explicit hmac_key wins; else key_ring / env."""
    if hmac_key is not None:
        raw = hmac_key.encode("utf-8") if isinstance(hmac_key, str) else hmac_key
        return raw, key_id
    ring = load_key_ring(key_ring) if key_ring is not None else None
    if ring and key_id:
        return lookup_key_ring(ring, key_id), key_id
    if ring and not key_id:
        # Prefer "default" then first key.
        if "default" in ring:
            return lookup_key_ring(ring, "default"), "default"
        if ring:
            kid = sorted(ring.keys())[0]
            return lookup_key_ring(ring, kid), kid
    for name in env_fallback:
        val = os.environ.get(name)
        if val:
            return val.encode("utf-8"), key_id or name
    return None, key_id


def load_key_ring(source: str | Path | dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if source is None:
        return {}
    if isinstance(source, dict):
        if "keys" in source:
            return {str(k): dict(v) for k, v in source["keys"].items()}
        return {str(k): dict(v) if isinstance(v, dict) else {"env": str(v)} for k, v in source.items()}
    path = Path(source)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ChainIntegrityError("key ring must be a JSON object")
    keys = data.get("keys") if "keys" in data else data
    if not isinstance(keys, dict):
        raise ChainIntegrityError("key ring missing keys object")
    return {str(k): dict(v) if isinstance(v, dict) else {"env": str(v)} for k, v in keys.items()}


def lookup_key_ring(ring: dict[str, dict[str, Any]], key_id: str) -> bytes:
    """Resolve HMAC/symmetric key material for key_id."""
    entry = ring.get(key_id)
    if entry is None:
        raise ChainIntegrityError(f"unknown key_id {key_id!r}")
    if "env" in entry:
        val = os.environ.get(str(entry["env"]))
        if not val:
            raise ChainIntegrityError(f"key_id {key_id!r} env {entry['env']!r} unset")
        return val.encode("utf-8")
    if "material" in entry:
        return str(entry["material"]).encode("utf-8")
    raise ChainIntegrityError(f"key_id {key_id!r} has no env/material")


def lookup_ed25519_public(ring: dict[str, dict[str, Any]], key_id: str) -> str:
    """Resolve Ed25519 public key (urlsafe-b64) from a key ring entry."""
    entry = ring.get(key_id)
    if entry is None:
        raise ChainIntegrityError(f"unknown key_id {key_id!r}")
    if entry.get("public_key"):
        return str(entry["public_key"]).strip()
    if entry.get("public_key_env"):
        val = os.environ.get(str(entry["public_key_env"]))
        if not val:
            raise ChainIntegrityError(
                f"key_id {key_id!r} public_key_env {entry['public_key_env']!r} unset"
            )
        return val.strip()
    raise ChainIntegrityError(f"key_id {key_id!r} has no ed25519 public_key")


def write_key_ring(path: str | Path, keys: dict[str, dict[str, Any]]) -> Path:
    out = Path(path)
    payload = {"format": "sage.keys.v1", "keys": keys}
    out.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return out
