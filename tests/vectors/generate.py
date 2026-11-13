"""Regenerate the conformance vectors in this directory (docs/spec/FORMAT.md section 11.2).

    python tests/vectors/generate.py

The expected outcome of every vector is written here by hand. Generation fails if the reference
implementation disagrees, so a regenerated set never silently encodes a behaviour change. The
artifacts contain timestamps and random ids, so regenerating changes their bytes; commit the result
only when the format itself changes.

Keys are public test material (FORMAT.md section 11.2). Never use them for real evidence.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "src"))

from sage.clock import set_clock  # noqa: E402
from sage.journal import CHAIN_JSONL, MANIFEST_NAME, SPANS_JSONL, attach_enriched_audit, save_journal  # noqa: E402
from sage.pack import attest_custody, compute_artifact_digest, custody_attestation_payload, pack_artifact  # noqa: E402
from sage.receipt import write_receipt  # noqa: E402
from sage.recorder import SageRecorder  # noqa: E402
from sage.signing import sign_payload  # noqa: E402
from sage.verify import verify_artifact  # noqa: E402

HMAC_KEY = "sage-conformance-hmac-key"
# RFC 8032 section 7.1, TEST 1.
RFC8032_SECRET = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
RFC8032_PUBLIC = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
OTHER_SECRET = hashlib.sha256(b"sage-conformance-other-signer").digest()
TAR_MTIME = 1767225600  # 2026-01-01T00:00:00Z


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


PRIVATE = b64u(RFC8032_SECRET)
PUBLIC = b64u(RFC8032_PUBLIC)

STRICT_POLICY = {
    "format": "sage.verify.policy.v1",
    "policy_id": "conformance-strict",
    "require_sealed": True,
    "forbid_live_journal": True,
    "require_witness": True,
    "require_witness_hmac": True,
    "require_pack_hmac": True,
    "require_pack_v2": True,
    "require_pack_signature": True,
    "require_blob_inventory": True,
    "min_span_count": 4,
}


class TickClock:
    """Each reading is 1 ms after the previous one, so span order is fixed."""

    def __init__(self) -> None:
        self._now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def now(self) -> datetime:
        self._now += timedelta(milliseconds=1)
        return self._now


# --------------------------------------------------------------------------------------------- record


def record(journal: Path, blobs: Path) -> None:
    with SageRecorder(
        "Conformance incident: refund tool timed out",
        trace_id="conformance",
        run_id="run_conformance",
        framework="custom",
        environment="conformance",
        metadata={"customer": "example", "api_key": "sk-conformance-not-a-real-key-0000"},
        blob_store=blobs,
        journal_dir=journal,
        journal_durability="span",
        register_trace=False,
    ) as rec:
        with rec.agent_step("support-agent", inputs={"goal": "refund order 1042"}):
            with rec.llm_call("plan", inputs={"prompt": "Plan a refund. Bearer abc.def.ghi"}) as llm:
                llm.set_model("conformance-model", temperature=0.0)
                llm.set_usage(input_tokens=12, output_tokens=7)
                llm.set_output(text="call refund_tool with é and 😀 and \u2028")
            with rec.retrieval("policy-lookup", inputs={"query": "refund window"}) as ret:
                ret.set_output(documents=[{"id": "doc-1", "text": "Refunds within 30 days. " * 60}])
            with rec.tool_call("refund_tool", inputs={"order": 1042, "amount": 19.99, "ratio": 1e-05}) as tool:
                tool.fail("upstream timeout after 30.0 s", error_type="TimeoutError")
                tool.mark_root_cause("refund service timed out", score=0.875)


# ------------------------------------------------------------------------------------------- helpers


def tar_dir(src_root: Path, out: Path, *, extra: list[tarfile.TarInfo] | None = None) -> None:
    """Deterministic tar.gz of `src_root/sage_artifact`."""
    out.parent.mkdir(parents=True, exist_ok=True)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        paths = [src_root / "sage_artifact", *sorted((src_root / "sage_artifact").rglob("*"))]
        for path in paths:
            info = tar.gettarinfo(str(path), arcname=path.relative_to(src_root).as_posix())
            info.mtime, info.uid, info.gid, info.uname, info.gname = TAR_MTIME, 0, 0, "", ""
            info.mode = 0o755 if path.is_dir() else 0o644
            if path.is_file():
                with path.open("rb") as handle:
                    tar.addfile(info, handle)
            else:
                tar.addfile(info)
        for info in extra or []:
            tar.addfile(info, io.BytesIO(b"x" * info.size) if info.size else None)
    import gzip

    out.write_bytes(gzip.compress(buf.getvalue(), mtime=0))


def unpack_raw(pack: Path, dest: Path) -> Path:
    with tarfile.open(pack, "r:gz") as tar:
        tar.extractall(dest, filter="data")
    return dest


def rewrite_pack_json(root: Path, edit, *, resign: bool = True) -> None:
    """Edit pack.json, then recompute its MAC and signature so only the edited rule can fail."""
    meta_path = root / "sage_artifact" / "pack.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    edit(meta)
    if resign:
        payload = custody_attestation_payload(
            content_digest=compute_artifact_digest(root / "sage_artifact"),
            bundle_hash=str(meta.get("bundle_hash") or ""),
            merkle_root=str(meta.get("merkle_root") or ""),
            blob_merkle=str(meta.get("blob_merkle") or ""),
            witness_tip=str(meta.get("witness_tip") or "no_witness"),
        )
        meta["attestation"]["mac"] = attest_custody(payload, HMAC_KEY)
        meta["attestation"]["witness_tip"] = payload["witness_tip"]
        meta["signature"] = sign_payload(payload, private_key=PRIVATE)
    meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")


def edit_jsonl(path: Path, index: int, edit) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[index])
    edit(obj)
    lines[index] = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def reseal_manifest(journal: Path, edit=None) -> None:
    from sage.journal import compute_manifest_seal

    manifest = json.loads((journal / MANIFEST_NAME).read_text(encoding="utf-8"))
    if edit:
        edit(manifest)
    manifest.pop("manifest_seal", None)
    manifest["manifest_seal"] = compute_manifest_seal(manifest)
    (journal / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


def resave_journal(journal: Path, edit) -> None:
    """Load, edit spans, and re-seal with valid hashes: only a non-hash rule can then fail."""
    from sage.bundle_io import load_bundle

    bundle = load_bundle(journal, verify=False, rehydrate=False)
    edit(bundle)
    attach_enriched_audit(bundle)
    save_journal(bundle, journal)


# ------------------------------------------------------------------------------------------- vectors

VECTORS: list[dict] = []


def vector(vid: str, kind: str, artifact: str, rule: str, expect: str, error_type: str | None = None,
           exit_code: int | None = None, **options) -> None:
    VECTORS.append({
        "id": vid,
        "kind": kind,
        "artifact": artifact,
        "rule": rule,
        "expect": expect,
        "error_type": error_type,
        "exit": exit_code if exit_code is not None else (0 if expect == "accept" else 1),
        **options,
    })


def main() -> None:
    clock = set_clock(TickClock())
    try:
        build()
    finally:
        set_clock(None)
        del clock


def build() -> None:
    for name in ("bundle", "journal", "pack", "kit", "policy", "keys"):
        shutil.rmtree(HERE / name, ignore_errors=True)
    keys = HERE / "keys"
    keys.mkdir()
    (keys / "hmac.key").write_text(HMAC_KEY + "\n", encoding="utf-8")
    (keys / "ed25519.public.txt").write_text(PUBLIC + "\n", encoding="utf-8")

    cwd = Path.cwd()
    work = Path(tempfile.mkdtemp(prefix="sage-vectors-"))
    os.chdir(work)  # the recorder stores the blob-store path in metadata; keep it relative
    try:
        record(Path("journal"), Path("blobs"))
        rec_journal, rec_blobs = work / "journal", work / "blobs"

        # ---- journal
        valid_j = HERE / "journal" / "valid"
        shutil.copytree(rec_journal, valid_j, ignore=shutil.ignore_patterns("*.wal.jsonl", "witness.jsonl"))
        for name in list(valid_j.iterdir()):
            if name.name not in (SPANS_JSONL, CHAIN_JSONL, MANIFEST_NAME):
                name.unlink()
        vector("journal/valid", "journal", "journal/valid", "6.2", "accept", blob_root="bundle/valid/blobs")

        def jvec(vid: str, rule: str, mutate, error_type: str, exit_code: int = 1) -> None:
            target = HERE / "journal" / vid
            shutil.copytree(valid_j, target)
            mutate(target)
            vector(f"journal/{vid}", "journal", f"journal/{vid}", rule, "reject", error_type, exit_code,
                   blob_root="bundle/valid/blobs")

        jvec("span-unknown-member", "3.1 normal form",
             lambda d: (edit_jsonl(d / SPANS_JSONL, 1, lambda s: s.__setitem__("x_unbound", "not hashed"))),
             "ChainIntegrityError")
        jvec("span-content-edited", "6.2 step 6",
             lambda d: edit_jsonl(d / SPANS_JSONL, 1, lambda s: s["data"].__setitem__("model", "other-model")),
             "AuditChainMismatchError")
        jvec("chain-link-edited", "6.2 step 6",
             lambda d: (edit_jsonl(d / CHAIN_JSONL, 2, lambda link: link.__setitem__("span_name", "renamed")),
                        reseal_manifest(d)),
             "AuditChainMismatchError")
        jvec("manifest-seal-broken", "6.2 step 2",
             lambda d: (d / MANIFEST_NAME).write_text(
                 (d / MANIFEST_NAME).read_text(encoding="utf-8").replace('"conformance"', '"Conformance"', 1),
                 encoding="utf-8"),
             "ChainIntegrityError")
        jvec("chain-tip-mismatch", "6.2 step 3",
             lambda d: reseal_manifest(d, lambda m: m.__setitem__("chain_tip", "1" * 64)), "ChainIntegrityError")
        jvec("merkle-root-mismatch", "6.2 step 3",
             lambda d: reseal_manifest(d, lambda m: m.__setitem__("merkle_root", "2" * 64)), "ChainIntegrityError")
        jvec("bundle-hash-mismatch", "6.2 step 6",
             lambda d: reseal_manifest(d, lambda m: m["audit"].__setitem__("bundle_hash", "3" * 64)),
             "AuditChainMismatchError")
        jvec("span-line-missing", "6.2 step 4",
             lambda d: (d / SPANS_JSONL).write_text(
                 "".join((d / SPANS_JSONL).read_text(encoding="utf-8").splitlines(keepends=True)[:-1]),
                 encoding="utf-8"),
             "ChainIntegrityError")
        jvec("torn-tail", "6.2 step 1",
             lambda d: (d / SPANS_JSONL).write_bytes((d / SPANS_JSONL).read_bytes() + b'{"span_id": "torn'),
             "FaultRecoveryError", 2)
        jvec("invalid-utf8", "11.1 malformed input",
             lambda d: (d / SPANS_JSONL).write_bytes(b"\xff\xfe" + (d / SPANS_JSONL).read_bytes()),
             "ChainIntegrityError")

        def dup_seq(bundle) -> None:
            bundle.spans[2].attributes["sage.seq"] = bundle.spans[1].attributes["sage.seq"]

        jvec("duplicate-seq-rehashed", "3.4", lambda d: resave_journal(d, dup_seq), "ChainIntegrityError")

        def child_before_parent(bundle) -> None:
            child = next(s for s in bundle.spans if s.parent_id)
            parent = next(s for s in bundle.spans if s.span_id == child.parent_id)
            child.attributes["sage.seq"], parent.attributes["sage.seq"] = (
                parent.attributes["sage.seq"], child.attributes["sage.seq"])

        jvec("parent-after-child-rehashed", "3.4", lambda d: resave_journal(d, child_before_parent),
             "ChainIntegrityError")

        def bad_type(bundle) -> None:
            bundle.spans[0].type = "spaceship"  # type: ignore[assignment]

        jvec("invalid-span-type-rehashed", "3.1", lambda d: resave_journal(d, bad_type), "ChainIntegrityError")

        # ---- bundle (.sage.json)
        from sage.bundle_io import load_bundle, save_bundle

        valid_b = HERE / "bundle" / "valid"
        valid_b.mkdir(parents=True)
        shutil.copytree(rec_blobs, valid_b / "blobs")
        bundle = load_bundle(rec_journal, verify=True, rehydrate=False)
        bundle.metadata["blob_store"] = "blobs"
        attach_enriched_audit(bundle)
        save_bundle(bundle, valid_b / "incident.sage.json")
        vector("bundle/valid", "bundle", "bundle/valid/incident.sage.json", "5", "accept",
               blob_root="bundle/valid/blobs")

        def bvec(vid: str, rule: str, mutate, error_type: str, blob_root: str = "bundle/valid/blobs") -> None:
            target = HERE / "bundle" / vid
            target.mkdir(parents=True)
            raw = json.loads((valid_b / "incident.sage.json").read_text(encoding="utf-8"))
            mutate(raw, target)
            (target / "incident.sage.json").write_text(json.dumps(raw, indent=2, sort_keys=True), encoding="utf-8")
            vector(f"bundle/{vid}", "bundle", f"bundle/{vid}/incident.sage.json", rule, "reject", error_type,
                   blob_root=blob_root)

        bvec("unknown-top-level-member", "5.3 normal form", lambda r, t: r.__setitem__("x_unbound", 1),
             "ChainIntegrityError")
        bvec("audit-chain-mirror-differs", "5.3 normal form",
             lambda r, t: r["audit_chain"][0].__setitem__("span_name", "mirror-edit"), "ChainIntegrityError")
        bvec("bundle-hash-edited", "5.4",
             lambda r, t: r["audit"].__setitem__("bundle_hash", "4" * 64), "AuditChainMismatchError")
        bvec("int-became-float", "2.2 rule 6",
             lambda r, t: r["spans"][-1]["inputs"].__setitem__("order", 1042.0), "AuditChainMismatchError")

        digest = next(p.name for p in (valid_b / "blobs").rglob("*") if p.is_file())
        missing = HERE / "bundle" / "blob-missing" / "blobs"

        def no_blob(r, t) -> None:
            missing.mkdir(parents=True)

        bvec("blob-missing", "4", no_blob, "ChainIntegrityError", blob_root="bundle/blob-missing/blobs")

        def altered_blob(r, t) -> None:
            shutil.copytree(valid_b / "blobs", t / "blobs")
            for path in (t / "blobs").rglob(digest + "*"):
                raw = path.read_bytes()
                path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))

        bvec("blob-altered", "4", altered_blob, "ChainIntegrityError", blob_root="bundle/blob-altered/blobs")

        # ---- pack
        packs = HERE / "pack"
        packs.mkdir()
        os.environ.pop("SAGE_SIGN_PRIVATE_KEY", None)
        built = pack_artifact(rec_journal, work / "evidence.sage.tar.gz", blob_store=rec_blobs, hmac_key=HMAC_KEY,
                              actor="conformance-producer", sign=True, private_key=PRIVATE)
        stage = unpack_raw(built, work / "stage")
        tar_dir(stage, packs / "valid.sage.tar.gz")
        pack_opts = {"hmac_key": True, "public_key": True, "policy": STRICT_POLICY}
        vector("pack/valid", "pack", "pack/valid.sage.tar.gz", "7.6", "accept", **pack_opts)
        second = pack_artifact(rec_journal, work / "second.sage.tar.gz", blob_store=rec_blobs, hmac_key=HMAC_KEY,
                               actor="second-producer", sign=True, private_key=PRIVATE)
        tar_dir(unpack_raw(second, work / "stage-second"), packs / "valid-second.sage.tar.gz")
        vector("pack/valid-second", "pack", "pack/valid-second.sage.tar.gz", "7.6", "accept", **pack_opts)

        def pvec(vid: str, rule: str, mutate, error_type: str, exit_code: int = 1, extra=None, **opts) -> None:
            root = work / f"p-{vid}"
            shutil.copytree(stage, root)
            if mutate:
                mutate(root / "sage_artifact")
            tar_dir(root, packs / f"{vid}.sage.tar.gz", extra=extra)
            vector(f"pack/{vid}", "pack", f"pack/{vid}.sage.tar.gz", rule, "reject", error_type, exit_code,
                   **{**pack_opts, **opts})

        art = "sage_artifact"
        pvec("pack-json-missing", "7.2", lambda a: (a / "pack.json").unlink(), "SignatureMismatchError")
        pvec("pack-json-missing-no-key", "7.2", lambda a: (a / "pack.json").unlink(), "ChainIntegrityError",
             hmac_key=False, public_key=False, policy=None)
        pvec("required-member-missing", "7.2",
             lambda a: rewrite_pack_json(a.parent, lambda m: m.pop("merkle_root")), "ChainIntegrityError")
        pvec("journal-byte-changed", "7.6 step 2",
             lambda a: (a / "journal" / MANIFEST_NAME).write_text(
                 (a / "journal" / MANIFEST_NAME).read_text(encoding="utf-8") + "\n", encoding="utf-8"),
             "ChainIntegrityError")
        pvec("blob-merkle-mismatch", "7.6 step 2",
             lambda a: rewrite_pack_json(a.parent, lambda m: m.__setitem__("blob_merkle", "5" * 64), resign=False),
             "ChainIntegrityError")
        pvec("wrong-hmac-key", "7.6 step 3", None, "ChainIntegrityError", hmac_key="not-the-conformance-key")
        pvec("attestation-stripped", "7.6 step 3",
             lambda a: rewrite_pack_json(a.parent, lambda m: m.pop("attestation"), resign=False),
             "ChainIntegrityError")

        def other_signer(a: Path) -> None:
            meta = json.loads((a / "pack.json").read_text(encoding="utf-8"))
            payload = custody_attestation_payload(
                content_digest=meta["content_digest"], bundle_hash=meta["bundle_hash"],
                merkle_root=meta["merkle_root"], blob_merkle=meta["blob_merkle"], witness_tip=meta["witness_tip"])
            meta["signature"] = sign_payload(payload, private_key=b64u(OTHER_SECRET))
            (a / "pack.json").write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")

        pvec("signed-by-other-key", "7.5", other_signer, "SignatureMismatchError")
        pvec("signature-stripped", "7.5",
             lambda a: rewrite_pack_json(a.parent, lambda m: m.pop("signature"), resign=False),
             "SignatureMismatchError")
        pvec("signature-without-pin", "7.5", None, "SignatureMismatchError", public_key=False,
             policy={**STRICT_POLICY})

        def extra_blob(a: Path) -> None:
            raw = b"unlisted payload"
            (a / "blobs" / hashlib.sha256(raw).hexdigest()).write_bytes(raw)
            rewrite_pack_json(a.parent, lambda m: None)

        pvec("blob-not-in-inventory", "7.6 step 5", extra_blob, "ChainIntegrityError")

        def renamed_blob(a: Path) -> None:
            blob = next((a / "blobs").iterdir())
            blob.write_bytes(blob.read_bytes() + b" ")
            rewrite_pack_json(a.parent, lambda m: None)

        pvec("blob-name-not-digest", "7.6 step 5", renamed_blob, "ChainIntegrityError")
        pvec("bundle-hash-anchor", "7.6 step 7",
             lambda a: rewrite_pack_json(a.parent, lambda m: m.__setitem__("bundle_hash", "6" * 64)),
             "ChainIntegrityError")
        pvec("merkle-root-anchor", "7.6 step 7",
             lambda a: rewrite_pack_json(a.parent, lambda m: m.__setitem__("merkle_root", "7" * 64)),
             "ChainIntegrityError")
        pvec("witness-tip-anchor", "7.6 step 7",
             lambda a: rewrite_pack_json(a.parent, lambda m: m.__setitem__("witness_tip", "8" * 64)),
             "ChainIntegrityError")

        def witness_edit(a: Path) -> None:
            edit_jsonl(a / "journal" / "witness.jsonl", 0, lambda r: r.__setitem__("actor", "someone-else"))
            rewrite_pack_json(a.parent, lambda m: None)

        pvec("witness-record-edited", "8", witness_edit, "ChainIntegrityError")

        def witness_mac_forged(a: Path) -> None:
            def forge(rec: dict) -> None:
                rec["attestation"]["mac"] = "9" * 64
                body = {k: v for k, v in rec.items() if k != "record_hash"}
                rec["record_hash"] = hashlib.sha256(
                    json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()

            edit_jsonl(a / "journal" / "witness.jsonl", 0, forge)
            tip = json.loads((a / "journal" / "witness.jsonl").read_text(encoding="utf-8").splitlines()[-1])
            rewrite_pack_json(a.parent, lambda m: m.__setitem__("witness_tip", tip["record_hash"]))

        pvec("witness-mac-forged", "8", witness_mac_forged, "ChainIntegrityError")

        def traversal(a: Path) -> None:
            pass

        evil = tarfile.TarInfo("sage_artifact/../escape.txt")
        evil.size, evil.mtime = 4, TAR_MTIME
        pvec("path-traversal-member", "7.1", traversal, "ChainIntegrityError", extra=[evil])
        link = tarfile.TarInfo("sage_artifact/journal/link")
        link.type, link.linkname, link.mtime = tarfile.SYMTYPE, "/etc/passwd", TAR_MTIME
        pvec("symlink-member", "7.1", traversal, "ChainIntegrityError", extra=[link])
        (packs / "not-gzip.sage.tar.gz").write_bytes(b"this is not a gzip stream\n" * 4)
        vector("pack/not-gzip", "pack", "pack/not-gzip.sage.tar.gz", "11.1 malformed input", "reject",
               "ChainIntegrityError", **pack_opts)
        pvec("policy-min-span-count", "9", None, "PolicyViolationError",
             policy={**STRICT_POLICY, "min_span_count": 99})

        # ---- kits (pack + policy + receipt), verified with the handoff helper
        report = verify_artifact(packs / "valid.sage.tar.gz", hmac_key=HMAC_KEY, witness_key=HMAC_KEY,
                                 public_key=PUBLIC, policy=STRICT_POLICY)

        def kit(vid: str, rule: str, expect: str, error_type: str | None, receipt_edit=None, pack: str = "valid",
                receipt_key: str = HMAC_KEY, exit_code: int | None = None) -> None:
            root = HERE / "kit" / vid
            root.mkdir(parents=True)
            shutil.copy2(packs / f"{pack}.sage.tar.gz", root / "evidence.sage.tar.gz")
            (root / "policy.json").write_text(json.dumps(STRICT_POLICY, indent=2, sort_keys=True), encoding="utf-8")
            write_receipt(report, root / "verify.receipt.json", hmac_key=receipt_key)
            if receipt_edit:
                path = root / "verify.receipt.json"
                data = json.loads(path.read_text(encoding="utf-8"))
                receipt_edit(data)
                path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
            vector(f"kit/{vid}", "kit", f"kit/{vid}", rule, expect, error_type, exit_code)

        kit("valid", "10", "accept", None)
        kit("receipt-mac-mismatch", "10", "reject", "ReceiptMismatchError",
            receipt_edit=lambda r: r.__setitem__("policy_id", "lenient"))
        kit("receipt-other-key", "10", "reject", "ReceiptMismatchError", receipt_key="another-key")
        kit("receipt-unsigned", "10", "reject", "ReceiptMismatchError", receipt_edit=lambda r: r.pop("attestation"))
        kit("receipt-for-other-pack", "10", "reject", "ReceiptMismatchError", pack="valid-second")

        # ---- policies
        pol = HERE / "policy"
        pol.mkdir()
        for vid, body in (
            ("unknown-member", {**STRICT_POLICY, "require_everything": True}),
            ("wrong-type", {**STRICT_POLICY, "require_pack_hmac": "yes"}),
            ("wrong-format", {**STRICT_POLICY, "format": "sage.verify.policy.v0"}),
        ):
            (pol / f"{vid}.json").write_text(json.dumps(body, indent=2, sort_keys=True), encoding="utf-8")
            vector(f"policy/{vid}", "policy", f"policy/{vid}.json", "9", "reject", "ChainIntegrityError")
        (pol / "strict.json").write_text(json.dumps(STRICT_POLICY, indent=2, sort_keys=True), encoding="utf-8")
        vector("policy/strict", "policy", "policy/strict.json", "9", "accept")
    finally:
        os.chdir(cwd)
        shutil.rmtree(work, ignore_errors=True)

    (HERE / "manifest.json").write_text(json.dumps({
        "format": "sage.conformance.vectors.v1",
        "spec": "docs/spec/FORMAT.md",
        "hmac_key_file": "keys/hmac.key",
        "public_key_file": "keys/ed25519.public.txt",
        "vectors": VECTORS,
    }, indent=2) + "\n", encoding="utf-8")

    from run_vectors import run  # noqa: E402

    failures = run(HERE)
    if failures:
        raise SystemExit("generated vectors disagree with the implementation:\n" + "\n".join(failures))
    print(f"wrote {len(VECTORS)} vectors")


if __name__ == "__main__":
    sys.path.insert(0, str(HERE))
    main()
