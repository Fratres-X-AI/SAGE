"""Optional Ed25519 signing (pip install -e '.[sign]').

Core remains stdlib-only. When cryptography is absent, signing APIs fail closed
with a clear install hint — HMAC attestation still works without this module.

Pinned verification: under ``require_signature``, an auditor-supplied public key
(env / arg / key ring) is mandatory. Embedded signature public_key is TOFU-only
and is refused when pinning is required.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

from sage.errors import ChainIntegrityError, SignatureMismatchError

def install_hint() -> str:
    """How to add Ed25519 support to the SAGE that is installed right now."""
    from sage.version import __version__

    return (
        f"Ed25519 signatures require the 'cryptography' package, which SAGE {__version__} in this "
        f"environment does not have: python -m pip install cryptography "
        f"(or reinstall with the extra: python -m pip install "
        f"\"<path to>/sage_incident_bundles-{__version__}-py3-none-any.whl[sign]\")"
    )


_CRYPTO_HINT = install_hint()
_PURE_VERIFY = False


def enable_pure_python_verification() -> None:
    """Let signature *verification* fall back to the bundled pure-Python Ed25519 when
    ``cryptography`` is missing. Used by the single-file verifier; signing still needs cryptography."""
    global _PURE_VERIFY
    _PURE_VERIFY = True


def signing_available() -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: F401

        return True
    except ImportError:
        return False


def verification_available() -> bool:
    return signing_available() or _PURE_VERIFY


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def generate_keypair() -> dict[str, str]:
    if not signing_available():
        raise ChainIntegrityError(_CRYPTO_HINT)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    priv_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "alg": "ed25519",
        "private_key": _b64e(priv_raw),
        "public_key": _b64e(pub_raw),
    }


def load_private_key(material: str | None = None):
    if not signing_available():
        raise ChainIntegrityError(_CRYPTO_HINT)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    raw = material or os.environ.get("SAGE_SIGN_PRIVATE_KEY")
    if not raw:
        raise ChainIntegrityError("missing Ed25519 private key (SAGE_SIGN_PRIVATE_KEY)")
    return Ed25519PrivateKey.from_private_bytes(_b64d(raw.strip()))


def load_public_key(material: str | None = None):
    if not verification_available():
        raise ChainIntegrityError(_CRYPTO_HINT)
    raw = material or os.environ.get("SAGE_SIGN_PUBLIC_KEY")
    if not raw:
        raise ChainIntegrityError("missing Ed25519 public key (SAGE_SIGN_PUBLIC_KEY)")
    if not signing_available():
        from sage._ed25519_verify import PurePublicKey

        return PurePublicKey(_b64d(raw.strip()))
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    return Ed25519PublicKey.from_public_bytes(_b64d(raw.strip()))


def public_key_fingerprint(material: str) -> str:
    """SHA-256 (hex) of the raw 32-byte Ed25519 public key encoded in ``material`` (urlsafe base64)."""
    import hashlib

    raw = _b64d(material.strip())
    if len(raw) != 32:
        raise ValueError(f"not an Ed25519 public key: decodes to {len(raw)} bytes, expected 32")
    return hashlib.sha256(raw).hexdigest()


def resolve_pinned_public_key(
    *,
    public_key: str | None = None,
    key_id: str | None = None,
    key_ring: str | Path | dict[str, Any] | None = None,
) -> str | None:
    """Resolve auditor-pinned public key material (never from a signature block)."""
    if public_key:
        return public_key.strip()
    env = os.environ.get("SAGE_SIGN_PUBLIC_KEY")
    if env:
        return env.strip()
    if key_ring is not None:
        from sage.keys import lookup_ed25519_public, load_key_ring

        ring = load_key_ring(key_ring)
        if key_id:
            return lookup_ed25519_public(ring, key_id)
        # Prefer sign / default / first ed25519 entry.
        for kid in ("sign", "default", *sorted(ring.keys())):
            if kid in ring and (
                ring[kid].get("public_key") or str(ring[kid].get("alg", "")).lower() == "ed25519"
            ):
                return lookup_ed25519_public(ring, kid)
    return None


def sign_payload(
    payload: dict[str, Any] | bytes,
    *,
    private_key: str | None = None,
    key_id: str | None = None,
) -> dict[str, Any]:
    """Sign canonical JSON (or raw bytes). Returns signature block."""
    if isinstance(payload, dict):
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    else:
        body = payload
    key = load_private_key(private_key)
    from cryptography.hazmat.primitives import serialization

    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    sig = key.sign(body)
    out = {
        "alg": "ed25519",
        "sig": _b64e(sig),
        "public_key": _b64e(pub),
    }
    if key_id:
        out["key_id"] = key_id
    return out


def verify_signature(
    payload: dict[str, Any] | bytes,
    signature: dict[str, Any],
    *,
    public_key: str | None = None,
    require_pinned: bool = False,
    key_id: str | None = None,
    key_ring: str | Path | dict[str, Any] | None = None,
) -> None:
    if not isinstance(signature, dict) or signature.get("alg") != "ed25519" or not signature.get("sig"):
        raise SignatureMismatchError("missing ed25519 signature block")
    if isinstance(payload, dict):
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    else:
        body = payload

    pinned = resolve_pinned_public_key(public_key=public_key, key_id=key_id, key_ring=key_ring)
    if require_pinned:
        if not pinned:
            raise ChainIntegrityError(
                "pinned Ed25519 public key required "
                "(SAGE_SIGN_PUBLIC_KEY / --public-key / key ring); TOFU refused"
            )
        pub_mat = pinned
    else:
        # Opportunistic: pinned wins, else embedded TOFU.
        pub_mat = pinned or signature.get("public_key")

    key = load_public_key(str(pub_mat) if pub_mat else None)
    try:
        key.verify(_b64d(str(signature["sig"])), body)
    except Exception as exc:  # cryptography InvalidSignature
        detail = str(exc) or "signature does not match the pinned public key"
        raise SignatureMismatchError(f"ed25519 signature verification failed: {detail}") from exc


def write_keypair(path: str | Path) -> Path:
    """Write a local keypair file (private material — gitignore this)."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    kp = generate_keypair()
    out.write_text(json.dumps(kp, indent=2, sort_keys=True), encoding="utf-8")
    try:
        os.chmod(out, 0o600)
    except OSError:
        pass
    return out
