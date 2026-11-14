from __future__ import annotations

import copy
import json
import os
import shutil
import uuid
import warnings
from collections.abc import Callable
from importlib import resources
from pathlib import Path
from typing import Any

from sage.errors import SageError
from sage.pack import pack_artifact
from sage.policy import VerifyPolicy, load_policy
from sage.receipt import write_receipt
from sage.verify import verify_artifact


class HandoffSetupError(SageError):
    """Handoff cannot be built as requested (missing key material, existing kit, bad input)."""


class HandoffLeakError(SageError):
    """The pre-share leak scan found possible secrets and ``fail_on_findings`` was set."""


class HandoffLeakWarning(UserWarning):
    """The pre-share leak scan found possible secrets; the kit was still built."""


HANDOFF_MD = """# SAGE Evidence Handoff

This directory is an offline-verifiable incident evidence kit.

## Contents

- `evidence.sage.tar.gz`: sealed pack (journal, content-addressed blobs, pack.json, witness log)
- `policy.json`: the verification policy the producer applied when building this kit
- `verify.receipt.json`: verification receipt bound to this pack and policy
- `verify_handoff.py`: recipient re-verification helper

Any other file a producer adds (for example `INCIDENT_SUMMARY.md` or `build_record.json`) is a
convenience note, not evidence. Only the pack, verified as below, is evidence.

Verification covers the files inside the pack and checks the gzip CRC-32 and length. It does not
bind the archive bytes (gzip header fields such as the mtime, or tar metadata). To pin the exact
file you received, compare the SHA-256 of `evidence.sage.tar.gz` with a value from the producer.

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
   python -m pip install "<path to>/sage_incident_bundles-<version>-py3-none-any.whl[sign]"
   ```

   If PowerShell blocks `Activate.ps1`, run `Set-ExecutionPolicy -Scope Process RemoteSigned`
   first, or skip activation and call `sage-venv\\Scripts\\python.exe` directly.

   If you cannot install packages, use the single-file verifier `sage-verify-<version>.pyz` instead
   (published with each SAGE release). It needs only Python 3.10 or newer, checks signatures
   without `cryptography`, and takes the same options with the kit directory first:

   ```bash
   python sage-verify-<version>.pyz <this directory> --hmac-key-file <keys>/hmac.key --public-key-file <keys>/ed25519.public.txt
   ```

   Only the wheel paths (`verify_handoff.py` and `sage handoff verify`) need `cryptography`, and
   only when the policy requires a signature.

   `<keys>` below is wherever you saved the key files you received separately (they are not in
   this directory).

2. Run the helper from inside this directory, pointing it at the key files (same command in bash
   and PowerShell). Omit an option the policy does not need.

   ```bash
   python verify_handoff.py --hmac-key-file <keys>/hmac.key --public-key-file <keys>/ed25519.public.txt
   ```

   - `--hmac-key-file` is needed when `policy.json` sets `require_pack_hmac` or `require_witness_hmac`.
   - `--public-key-file` is needed when `policy.json` sets `require_pack_signature`.

   With SAGE 2.3 or newer installed, `sage handoff verify <this directory> --hmac-key-file ...
   --public-key-file ...` does the same from anywhere. The keys can also come from the
   `SAGE_PACK_KEY` and `SAGE_SIGN_PUBLIC_KEY` environment variables.

3. Compare `pinned_key_fingerprint` in the output with the fingerprint you received out of band.
   It is the SHA-256 of the raw 32-byte key (the urlsafe-base64-decoded file contents). Compute it
   independently of the helper with `sage key fingerprint <keys>/ed25519.public.txt`, or without SAGE
   (same command in bash and PowerShell):

   ```bash
   python -c "import base64,hashlib,sys; k=open(sys.argv[1]).read().strip(); print(hashlib.sha256(base64.urlsafe_b64decode(k + '=' * (-len(k) % 4))).hexdigest())" <keys>/ed25519.public.txt
   ```

   If the fingerprints differ, stop. Do not trust the kit, even if the helper reported `ok`.
   Contact the producer through the trusted channel.

On failure, `error_type` names what failed: `SignatureMismatchError` (signature missing or made with
a different key), `ReceiptMismatchError` (receipt altered or for another pack or policy),
`PolicyViolationError` (evidence breaks the policy), or `ChainIntegrityError` / `BlobIntegrityError`
(evidence altered).

Exit codes: `0` evidence, policy, and receipt all verified; `1` integrity, policy, or receipt
failure (the evidence or kit does not match); `2` setup problem (SAGE or `cryptography` not
installed, required key not provided, key file unreadable, kit file missing). The `.pyz` uses the
same codes. `sage key fingerprint` exits `0` on success and `2` when the key file is missing or
not a valid key.
"""


VERIFY_SCRIPT = resources.files("sage").joinpath("handoff_verify.py").read_text(encoding="utf-8")


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


def _leak_check(
    pack_path: Path,
    *,
    fail_on_findings: bool,
    on_findings: Callable[[Any], None] | None,
) -> None:
    from sage.scan import scan_path

    report = scan_path(pack_path)
    if report.ok:
        return
    if fail_on_findings:
        raise HandoffLeakError(
            f"pre-share leak scan: {report.summary()}; handoff not built. "
            "Run `sage scan` on the source for locations (values are never printed)."
        )
    if on_findings is not None:
        on_findings(report)
    else:
        warnings.warn(
            f"pre-share leak scan: {report.summary()}. Run `sage scan` on the kit's pack for locations.",
            HandoffLeakWarning,
            stacklevel=3,
        )


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
    blob_root: str | Path | None = None,
    scan: bool = True,
    fail_on_findings: bool = False,
    on_scan_findings: Callable[[Any], None] | None = None,
) -> Path:
    """Build an offline evidence handoff directory from a bundle, journal, or pack.

    An explicit ``policy`` is enforced as given; it is never weakened to fit missing keys.
    The kit is assembled in a staging directory and promoted only after verification and
    receipt generation succeed.

    The pack is run through `sage.scan.scan_path` first. Findings call ``on_scan_findings``
    with the `ScanReport` (default: a `HandoffLeakWarning`), or raise `HandoffLeakError` when
    ``fail_on_findings`` is set. Neither ever includes the values found.
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
                blob_store=blob_root,
            )
        if scan:
            _leak_check(pack_path, fail_on_findings=fail_on_findings, on_findings=on_scan_findings)
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
