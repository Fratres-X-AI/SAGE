from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import tarfile
import tempfile
from pathlib import Path

from sage.blobs import BLOB_MARKER, BlobStore, is_blob_ref, require_digest
from sage.bundle_io import load_bundle
from sage.errors import ChainIntegrityError
from sage.journal import save_journal
from sage.merkle import chain_merkle_root, merkle_root
from sage.schema import SCHEMA_VERSION

MAX_PACK_MEMBERS = 10_000
MAX_PACK_TOTAL_BYTES = 512 * 1024 * 1024  # 512 MiB portable evidence budget
MAX_PACK_MEMBER_BYTES = 256 * 1024 * 1024


def safe_extract_tar(tar: tarfile.TarFile, dest: Path) -> None:
    """Fail-closed tar extract: no traversal, no links/devices, bounded size."""
    dest = dest.resolve()
    total = 0
    members = tar.getmembers()
    if len(members) > MAX_PACK_MEMBERS:
        raise ChainIntegrityError(f"pack member count exceeds limit ({MAX_PACK_MEMBERS})")
    for member in members:
        name = member.name.replace("\\", "/")
        if name.startswith("/") or name.startswith("\\") or ".." in Path(name).parts:
            raise ChainIntegrityError(f"pack path traversal blocked: {member.name!r}")
        if member.issym() or member.islnk() or member.isdev() or member.isfifo():
            raise ChainIntegrityError(f"pack rejects special member type: {member.name!r}")
        target = (dest / name).resolve()
        if dest not in target.parents and target != dest:
            raise ChainIntegrityError(f"pack extract escape blocked: {member.name!r}")
        size = int(member.size or 0)
        if size > MAX_PACK_MEMBER_BYTES:
            raise ChainIntegrityError(f"pack member too large: {member.name!r} size={size}")
        total += size
        if total > MAX_PACK_TOTAL_BYTES:
            raise ChainIntegrityError(f"pack total size exceeds limit ({MAX_PACK_TOTAL_BYTES})")
        try:
            tar.extract(member, path=dest, filter="data")
        except TypeError:
            tar.extract(member, path=dest)


def _collect_blob_digests(value: object, out: set[str]) -> None:
    if is_blob_ref(value):
        out.add(str(value[BLOB_MARKER]))  # type: ignore[index]
        return
    if isinstance(value, dict):
        for child in value.values():
            _collect_blob_digests(child, out)
    elif isinstance(value, list):
        for child in value:
            _collect_blob_digests(child, out)


def collect_bundle_blob_digests(bundle) -> set[str]:
    digests: set[str] = set()
    for span in bundle.spans:
        for field in (span.inputs, span.outputs, span.attributes, span.data):
            _collect_blob_digests(field, digests)
    return digests


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def compute_artifact_digest(root: Path) -> str:
    """Canonical digest over all files under root except pack.json."""
    entries: list[tuple[str, str]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel == "pack.json":
            continue
        entries.append((rel, _file_sha256(path)))
    payload = json.dumps(entries, separators=(",", ":"), sort_keys=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def attest_digest(content_digest: str, key: bytes | str) -> str:
    """v1: HMAC over content_digest string only."""
    raw = key.encode("utf-8") if isinstance(key, str) else key
    return hmac.new(raw, content_digest.encode("utf-8"), hashlib.sha256).hexdigest()


def custody_attestation_payload(
    *,
    content_digest: str,
    bundle_hash: str,
    merkle_root: str,
    blob_merkle: str,
    witness_tip: str,
) -> dict:
    return {
        "blob_merkle": blob_merkle,
        "bundle_hash": bundle_hash,
        "content_digest": content_digest,
        "merkle_root": merkle_root,
        "witness_tip": witness_tip,
    }


def attest_custody(payload: dict, key: bytes | str) -> str:
    """v2: HMAC over canonical custody tuple (content + semantic anchors)."""
    raw = key.encode("utf-8") if isinstance(key, str) else key
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(raw, body, hashlib.sha256).hexdigest()


def _sage_version() -> str:
    try:
        from importlib.metadata import version

        return version("sage-incident-bundles")
    except Exception:
        return "unknown"


def _redaction_summary(bundle) -> dict:
    policy = bundle.redaction_policy or {}
    return {
        "redaction_count": len(bundle.redactions or []),
        "policy_fingerprint": hashlib.sha256(
            json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()[:16],
        "key_fragments": list(policy.get("key_fragments") or [])[:32],
    }


def verify_pack_meta(
    meta: dict,
    *,
    content_digest: str,
    hmac_key: bytes | str | None = None,
    require_signature: bool = False,
    public_key: str | None = None,
    allow_tofu_signature: bool = False,
    key_id: str | None = None,
    key_ring: str | Path | dict | None = None,
) -> None:
    claimed = meta.get("content_digest")
    if claimed and claimed != content_digest:
        raise ChainIntegrityError(
            f"pack content_digest mismatch: claimed={claimed!r} actual={content_digest!r}"
        )
    claimed_blobs = meta.get("blob_digests")
    claimed_merkle = meta.get("blob_merkle")
    if claimed_blobs is not None and claimed_merkle:
        actual = merkle_root([str(d) for d in claimed_blobs])
        if actual != claimed_merkle:
            raise ChainIntegrityError(
                f"pack blob_merkle mismatch: claimed={claimed_merkle!r} actual={actual!r}"
            )
    att = meta.get("attestation") or {}
    version = int(att.get("version") or (2 if meta.get("format") == "sage.pack.v2" else 1))
    custody_payload = custody_attestation_payload(
        content_digest=content_digest,
        bundle_hash=str(meta.get("bundle_hash") or ""),
        merkle_root=str(meta.get("merkle_root") or ""),
        blob_merkle=str(meta.get("blob_merkle") or ""),
        witness_tip=str(meta.get("witness_tip") or att.get("witness_tip") or "no_witness"),
    )
    if hmac_key is not None:
        if not att or att.get("alg") != "hmac-sha256" or not att.get("mac"):
            raise ChainIntegrityError("pack missing hmac-sha256 attestation")
        if version >= 2:
            expected = attest_custody(custody_payload, hmac_key)
        else:
            expected = attest_digest(content_digest, hmac_key)
        if not hmac.compare_digest(str(att["mac"]), expected):
            raise ChainIntegrityError("pack attestation MAC mismatch")
    elif att.get("mac") and att.get("alg") == "hmac-sha256":
        # Presence without key: still require content_digest match above.
        pass

    sig = meta.get("signature")
    if require_signature or sig:
        from sage.signing import verify_signature

        if not sig:
            raise ChainIntegrityError("pack missing ed25519 signature")
        # require_signature ⇒ pinned key (TOFU refused unless allow_tofu_signature).
        verify_signature(
            custody_payload,
            sig,
            public_key=public_key,
            require_pinned=bool(require_signature) and not allow_tofu_signature,
            key_id=key_id,
            key_ring=key_ring,
        )


def pack_artifact(
    path: str | Path,
    out_path: str | Path,
    *,
    blob_store: str | Path | BlobStore | None = None,
    hmac_key: bytes | str | None = None,
    actor: str = "local",
    write_witness: bool = True,
    pack_version: int = 2,
    key_id: str | None = None,
    sign: bool | None = None,
    private_key: str | None = None,
) -> Path:
    """Pack a .sage.json or journal dir into a portable .sage.tar.gz with blobs."""
    src = Path(path)
    out = Path(out_path)
    if not str(out).endswith(".tar.gz"):
        out = Path(str(out) + ".sage.tar.gz")

    key = hmac_key if hmac_key is not None else os.environ.get("SAGE_PACK_KEY")

    bundle = load_bundle(src, verify=True, rehydrate=False)
    digests = collect_bundle_blob_digests(bundle)
    meta = bundle.metadata or {}
    store = (
        blob_store
        if isinstance(blob_store, BlobStore)
        else BlobStore(blob_store or meta.get("blob_store"))
    )

    with tempfile.TemporaryDirectory(prefix="sage-pack-") as tmp:
        root = Path(tmp) / "artifact"
        root.mkdir()
        # Always pack as journal for crash-safe transport.
        journal_dir = root / "journal"
        save_journal(bundle, journal_dir)
        witness_tip = "no_witness"
        if write_witness:
            from sage.witness import append_witness

            tip = bundle.audit.chain[-1]["hash"] if bundle.audit.chain else "0" * 64
            rec = append_witness(
                journal_dir,
                action="pack",
                bundle_hash=bundle.audit.bundle_hash,
                chain_tip=tip,
                actor=actor,
                hmac_key=key,
                key_id=key_id,
            )
            witness_tip = str(rec.get("record_hash") or "no_witness")
        blob_dir = root / "blobs"
        blob_dir.mkdir()
        sorted_digests = sorted(digests)
        for digest in sorted_digests:
            raw = store.get_bytes(digest, verify=True)
            # Store uncompressed in pack for portability; CAS address is content hash.
            (blob_dir / digest).write_bytes(raw)

        content_digest = compute_artifact_digest(root)
        chain_merkle = chain_merkle_root(bundle.audit.chain)
        blob_m = merkle_root(sorted_digests)
        fmt = "sage.pack.v2" if pack_version >= 2 else "sage.pack.v1"
        pack_meta: dict = {
            "format": fmt,
            "sage_version": _sage_version(),
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "schema_version": SCHEMA_VERSION,
            "bundle_id": bundle.bundle_id,
            "bundle_hash": bundle.audit.bundle_hash,
            "blob_count": len(sorted_digests),
            "blob_digests": sorted_digests,
            "blob_merkle": blob_m,
            "content_digest": content_digest,
            "merkle_root": chain_merkle,
            "witness_tip": witness_tip,
            "redaction_summary": _redaction_summary(bundle),
        }
        if key:
            if pack_version >= 2:
                payload = custody_attestation_payload(
                    content_digest=content_digest,
                    bundle_hash=bundle.audit.bundle_hash,
                    merkle_root=chain_merkle,
                    blob_merkle=blob_m,
                    witness_tip=witness_tip,
                )
                att = {
                    "alg": "hmac-sha256",
                    "version": 2,
                    "mac": attest_custody(payload, key),
                    "witness_tip": witness_tip,
                }
            else:
                att = {
                    "alg": "hmac-sha256",
                    "version": 1,
                    "mac": attest_digest(content_digest, key),
                }
            if key_id:
                att["key_id"] = key_id
            pack_meta["attestation"] = att

        want_sign = sign if sign is not None else bool(
            private_key or os.environ.get("SAGE_SIGN_PRIVATE_KEY")
        )
        if want_sign:
            from sage.signing import sign_payload

            if pack_version >= 2:
                sign_body = custody_attestation_payload(
                    content_digest=content_digest,
                    bundle_hash=bundle.audit.bundle_hash,
                    merkle_root=chain_merkle,
                    blob_merkle=blob_m,
                    witness_tip=witness_tip,
                )
            else:
                sign_body = {"content_digest": content_digest, "bundle_hash": bundle.audit.bundle_hash}
            pack_meta["signature"] = sign_payload(sign_body, private_key=private_key, key_id=key_id)

        meta_path = root / "pack.json"
        meta_path.write_text(
            json.dumps(pack_meta, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        out.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(out, "w:gz") as tar:
            tar.add(root, arcname="sage_artifact")
    return out


def _materialize_unpacked(
    artifact: Path,
    dest: Path,
    *,
    blob_root: str | Path | None,
    hmac_key: bytes | str | None,
    verify_attestation: bool,
    require_signature: bool,
    public_key: str | None,
    actor: str,
    write_witness: bool,
    allow_tofu_signature: bool = False,
    key_id: str | None = None,
    key_ring: str | Path | dict | None = None,
) -> Path:
    journal = artifact / "journal"
    blobs_src = artifact / "blobs"
    meta_path = artifact / "pack.json"
    key = hmac_key if hmac_key is not None else os.environ.get("SAGE_PACK_KEY")

    meta: dict = {}
    if meta_path.exists():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if verify_attestation:
            content_digest = compute_artifact_digest(artifact)
            verify_pack_meta(
                meta,
                content_digest=content_digest,
                hmac_key=key if key else None,
                require_signature=require_signature,
                public_key=public_key,
                allow_tofu_signature=allow_tofu_signature,
                key_id=key_id,
                key_ring=key_ring,
            )

    store = BlobStore(blob_root or (dest / "blobs"))
    actual_blob_names: set[str] = set()
    if blobs_src.exists():
        for path in sorted(blobs_src.iterdir()):
            if path.is_file() and not path.name.startswith("."):
                digest_name = require_digest(path.name)
                actual_blob_names.add(digest_name)

                def _chunks(p: Path = path):
                    with p.open("rb") as handle:
                        while True:
                            block = handle.read(1024 * 1024)
                            if not block:
                                break
                            yield block

                put_digest = store.put_stream(_chunks(), expected_size=path.stat().st_size)
                if put_digest != digest_name:
                    raise ChainIntegrityError(
                        f"packed blob filename/digest mismatch: name={digest_name} actual={put_digest}"
                    )
    claimed = meta.get("blob_digests")
    if claimed is not None and verify_attestation:
        claimed_set = {require_digest(str(d)) for d in claimed}
        if claimed_set != actual_blob_names:
            raise ChainIntegrityError(
                f"pack blob inventory mismatch: claimed={sorted(claimed_set)[:5]} "
                f"actual={sorted(actual_blob_names)[:5]}"
            )
    custody_hash = str(meta.get("bundle_hash") or "")
    bundle = load_bundle(journal, verify=True, rehydrate=False)
    if not custody_hash:
        custody_hash = bundle.audit.bundle_hash
    bundle.metadata["blob_store"] = str(store.root)
    bundle.metadata["pack_bundle_hash"] = custody_hash
    save_journal(bundle, journal)
    if write_witness:
        from sage.witness import append_witness

        tip = bundle.audit.chain[-1]["hash"] if bundle.audit.chain else "0" * 64
        append_witness(
            journal,
            action="unpack",
            bundle_hash=custody_hash,
            chain_tip=tip,
            actor=actor,
            hmac_key=key,
            extra={"local_bundle_hash": bundle.audit.bundle_hash},
        )
    return journal


def unpack_artifact(
    pack_path: str | Path,
    out_dir: str | Path,
    *,
    blob_root: str | Path | None = None,
    hmac_key: bytes | str | None = None,
    verify_attestation: bool = True,
    actor: str = "local",
    write_witness: bool = True,
    quarantine: bool = True,
    require_signature: bool = False,
    public_key: str | None = None,
    allow_tofu_signature: bool = False,
    key_id: str | None = None,
    key_ring: str | Path | dict | None = None,
) -> Path:
    """Unpack a .sage.tar.gz into a journal directory and restore blobs.

    quarantine=True (default): extract + verify in a staging dir, then promote.
    Failed verify leaves ``out_dir`` untouched.
    """
    import shutil

    pack = Path(pack_path)
    dest = Path(out_dir)
    key = hmac_key if hmac_key is not None else os.environ.get("SAGE_PACK_KEY")
    req_sig = require_signature or bool(os.environ.get("SAGE_REQUIRE_PACK_SIGNATURE"))

    if not quarantine:
        dest.mkdir(parents=True, exist_ok=True)
        with tarfile.open(pack, "r:gz") as tar:
            safe_extract_tar(tar, dest)
        return _materialize_unpacked(
            dest / "sage_artifact",
            dest,
            blob_root=blob_root,
            hmac_key=key,
            verify_attestation=verify_attestation,
            require_signature=req_sig,
            public_key=public_key,
            actor=actor,
            write_witness=write_witness,
            allow_tofu_signature=allow_tofu_signature,
            key_id=key_id,
            key_ring=key_ring,
        )

    with tempfile.TemporaryDirectory(prefix="sage-quarantine-") as tmp:
        staging = Path(tmp) / "stage"
        staging.mkdir()
        with tarfile.open(pack, "r:gz") as tar:
            safe_extract_tar(tar, staging)
        # Always materialize blobs inside staging so promote cannot rmtree an
        # external blob_root (e.g. verify()'s TemporaryDirectory /blobs).
        stage_blobs = staging / "blobs"
        _materialize_unpacked(
            staging / "sage_artifact",
            staging,
            blob_root=stage_blobs,
            hmac_key=key,
            verify_attestation=verify_attestation,
            require_signature=req_sig,
            public_key=public_key,
            actor=actor,
            write_witness=write_witness,
            allow_tofu_signature=allow_tofu_signature,
            key_id=key_id,
            key_ring=key_ring,
        )

        dest.mkdir(parents=True, exist_ok=True)
        for name in ("sage_artifact",):
            prior = dest / name
            if prior.exists():
                shutil.rmtree(prior) if prior.is_dir() else prior.unlink()
        shutil.copytree(staging / "sage_artifact", dest / "sage_artifact")

        final_blobs = Path(blob_root) if blob_root is not None else (dest / "blobs")
        final_blobs.mkdir(parents=True, exist_ok=True)
        if stage_blobs.exists():
            for blob_path in stage_blobs.iterdir():
                if blob_path.is_file():
                    shutil.copy2(blob_path, final_blobs / blob_path.name)

        final_journal = dest / "sage_artifact" / "journal"
        bundle = load_bundle(final_journal, verify=True, rehydrate=False)
        bundle.metadata["blob_store"] = str(final_blobs)
        save_journal(bundle, final_journal)
        return final_journal

