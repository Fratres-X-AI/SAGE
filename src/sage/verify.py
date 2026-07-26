from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Literal

from sage.blobs import BlobStore
from sage.bundle_io import load_bundle
from sage.errors import BlobIntegrityError, ChainIntegrityError, FaultRecoveryError
from sage.journal import is_journal_path, journal_root, verify_journal
from sage.merkle import merkle_root
from sage.pack import collect_bundle_blob_digests, unpack_artifact
from sage.policy import VerifyPolicy, apply_policy, load_policy

ArtifactKind = Literal["bundle", "journal", "pack"]


def detect_artifact_kind(path: str | Path) -> ArtifactKind:
    p = Path(path)
    name = p.name.lower()
    if name.endswith(".sage.tar.gz") or (name.endswith(".tar.gz") and "sage" in name):
        return "pack"
    if is_journal_path(p):
        return "journal"
    if p.is_file() and (name.endswith(".sage.json") or name.endswith(".json")):
        return "bundle"
    if p.is_dir() and ((p / "sage_artifact" / "pack.json").exists() or (p / "pack.json").exists()):
        return "pack"
    if p.is_dir():
        return "journal"
    return "bundle"


def verify_blob_inventory(
    bundle,
    *,
    blob_root: str | Path | None = None,
) -> dict[str, Any]:
    """Fail-closed: every CAS ref present and content-addressed (streaming verify)."""
    digests = sorted(collect_bundle_blob_digests(bundle))
    meta = bundle.metadata or {}
    root = blob_root or meta.get("blob_store")
    if not digests:
        return {"ok": True, "blob_count": 0, "blob_merkle": merkle_root([]), "verified": []}
    if not root:
        raise ChainIntegrityError(
            f"bundle references {len(digests)} CAS blobs but no blob_store / --blob-root"
        )
    store = BlobStore(root)
    verified: list[str] = []
    missing: list[str] = []
    for digest in digests:
        if not store.exists(digest):
            missing.append(digest)
            continue
        try:
            store.verify_blob(digest)
        except BlobIntegrityError as exc:
            raise ChainIntegrityError(str(exc)) from exc
        verified.append(digest)
    if missing:
        raise ChainIntegrityError(f"missing CAS blobs: {missing[:5]}{'...' if len(missing) > 5 else ''}")
    return {
        "ok": True,
        "blob_count": len(verified),
        "blob_merkle": merkle_root(verified),
        "blob_root": str(store.root),
        "verified": verified,
    }


def _sage_version() -> str:
    try:
        from importlib.metadata import version

        return version("sage-incident-bundles")
    except Exception:
        return "unknown"


def verify_artifact(
    path: str | Path,
    *,
    require_sealed: bool = True,
    blob_root: str | Path | None = None,
    hmac_key: bytes | str | None = None,
    check_blobs: bool = True,
    check_witness: bool = False,
    witness_key: bytes | str | None = None,
    policy: str | Path | dict[str, Any] | VerifyPolicy | None = None,
    require_witness_hmac: bool = False,
    require_signature: bool = False,
    public_key: str | None = None,
    allow_tofu_signature: bool = False,
    key_id: str | None = None,
    key_ring: str | Path | dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Unified fail-closed verify for .sage.json / journal / .sage.tar.gz.

    Exit-code mapping for CLI: ok→0, integrity→1, recoverable fault→2.
    Always verifies compact (non-rehydrated) form for hash binding.
    """
    pol = (
        policy
        if isinstance(policy, VerifyPolicy)
        else (load_policy(policy) if policy is not None else None)
    )
    if pol is not None:
        require_sealed = pol.require_sealed and pol.forbid_live_journal
        check_blobs = pol.require_blob_inventory
        check_witness = check_witness or pol.require_witness or pol.require_witness_hmac
        require_witness_hmac = require_witness_hmac or pol.require_witness_hmac
        require_signature = require_signature or pol.require_pack_signature

    src = Path(path)
    kind = detect_artifact_kind(src)
    report: dict[str, Any] = {
        "ok": True,
        "kind": kind,
        "path": str(src),
        "sage_version": _sage_version(),
        "compact": True,
    }

    try:
        if kind == "pack":
            with tempfile.TemporaryDirectory(prefix="sage-verify-") as tmp:
                journal = unpack_artifact(
                    src,
                    tmp,
                    blob_root=blob_root or (Path(tmp) / "blobs"),
                    hmac_key=hmac_key,
                    verify_attestation=True,
                    quarantine=True,
                    require_signature=require_signature,
                    public_key=public_key,
                    allow_tofu_signature=allow_tofu_signature,
                    key_id=key_id,
                    key_ring=key_ring,
                )
                if hmac_key:
                    report["pack_hmac_verified"] = True
                if require_signature:
                    report["pack_signature_required"] = True
                    report["pack_signature_pinned"] = not allow_tofu_signature
                j_report = verify_journal(journal, allow_live=not require_sealed)
                report["journal"] = j_report
                report["span_count"] = j_report.get("span_count")
                bundle = load_bundle(journal, verify=True, rehydrate=False)
                pack_meta_path = Path(tmp) / "sage_artifact" / "pack.json"
                pack_meta = {}
                if pack_meta_path.exists():
                    pack_meta = json.loads(pack_meta_path.read_text(encoding="utf-8"))
                    report["pack"] = pack_meta
                if check_blobs:
                    report["blobs"] = verify_blob_inventory(
                        bundle, blob_root=blob_root or (Path(tmp) / "blobs")
                    )
                report["bundle_id"] = bundle.bundle_id
                report["bundle_hash"] = str(
                    pack_meta.get("bundle_hash")
                    or bundle.metadata.get("pack_bundle_hash")
                    or bundle.audit.bundle_hash
                )
                report["local_bundle_hash"] = bundle.audit.bundle_hash
                report["redaction_count"] = int(
                    (pack_meta.get("redaction_summary") or {}).get("redaction_count") or 0
                )
                if check_witness:
                    from sage.witness import verify_witness_log

                    tip = str(
                        j_report.get("chain_tip")
                        or (bundle.audit.chain[-1]["hash"] if bundle.audit.chain else "")
                    )
                    report["witness"] = verify_witness_log(
                        journal,
                        hmac_key=witness_key or hmac_key,
                        expect_bundle_hash=report["bundle_hash"],
                        expect_chain_tip=tip or None,
                        require_hmac=require_witness_hmac,
                    )
                if pol is not None:
                    apply_policy(report, pol)
                return report

        if kind == "journal":
            root = journal_root(src)
            j_report = verify_journal(root, allow_live=not require_sealed)
            report["journal"] = j_report
            report["span_count"] = j_report.get("span_count")
            if j_report.get("live"):
                report["bundle_id"] = j_report.get("bundle_id")
                report["live"] = True
                if pol is not None:
                    apply_policy(report, pol)
                return report
            bundle = load_bundle(root, verify=True, rehydrate=False)
            report["bundle_id"] = bundle.bundle_id
            report["bundle_hash"] = bundle.audit.bundle_hash
            report["span_count"] = len(bundle.spans)
            report["redaction_count"] = len(bundle.redactions or [])
            if check_blobs:
                report["blobs"] = verify_blob_inventory(bundle, blob_root=blob_root)
            if check_witness:
                from sage.witness import verify_witness_log

                tip = str(
                    j_report.get("chain_tip")
                    or (bundle.audit.chain[-1]["hash"] if bundle.audit.chain else "")
                )
                report["witness"] = verify_witness_log(
                    root,
                    hmac_key=witness_key or hmac_key,
                    expect_bundle_hash=bundle.audit.bundle_hash,
                    expect_chain_tip=tip or None,
                    require_hmac=require_witness_hmac,
                )
            if pol is not None:
                apply_policy(report, pol)
            return report

        # bundle (.sage.json)
        bundle = load_bundle(src, verify=True, rehydrate=False)
        report["bundle_id"] = bundle.bundle_id
        report["bundle_hash"] = bundle.audit.bundle_hash
        report["span_count"] = len(bundle.spans)
        report["redaction_count"] = len(bundle.redactions or [])
        if check_blobs:
            report["blobs"] = verify_blob_inventory(bundle, blob_root=blob_root)
        if check_witness:
            from sage.witness import verify_witness_log

            tip = bundle.audit.chain[-1]["hash"] if bundle.audit.chain else None
            report["witness"] = verify_witness_log(
                src.parent,
                hmac_key=witness_key or hmac_key,
                expect_bundle_hash=bundle.audit.bundle_hash,
                expect_chain_tip=tip,
                require_hmac=require_witness_hmac,
            )
        if pol is not None:
            apply_policy(report, pol)
        return report
    except FaultRecoveryError as exc:
        report["ok"] = False
        report["error"] = str(exc)
        report["recoverable"] = True
        raise
    except (ChainIntegrityError, BlobIntegrityError) as exc:
        report["ok"] = False
        report["error"] = str(exc)
        report["recoverable"] = False
        raise
