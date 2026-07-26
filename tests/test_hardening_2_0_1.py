from __future__ import annotations

import json
import tarfile
from pathlib import Path

import pytest

from sage.blobs import BlobStore, require_digest
from sage.errors import BlobIntegrityError, ChainIntegrityError, SecurityDivergence
from sage.heal_capability import HealCapability
from sage.journal import SPANS_JSONL, verify_journal
from sage.pack import pack_artifact, safe_extract_tar, unpack_artifact
from sage.policy import load_policy
from sage.receipt import verify_receipt, write_receipt
from sage.recorder import SageRecorder
from sage.replay import apply_heal
from sage.verify import verify_artifact


def test_live_journal_tampered_span_fail_closed(tmp_path: Path):
    journal = tmp_path / "j"
    with SageRecorder("live", journal_dir=journal, register_trace=False) as rec:
        with rec.tool_call("t", inputs={"x": 1}):
            pass
        report = verify_journal(journal, allow_live=True)
        assert report["content_verified"] is True
        # Tamper span body after chain write.
        lines = (journal / SPANS_JSONL).read_text(encoding="utf-8").splitlines()
        obj = json.loads(lines[0])
        obj["inputs"]["x"] = 999
        (journal / SPANS_JSONL).write_text(
            json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        with pytest.raises(ChainIntegrityError, match="content_hash|link hash"):
            verify_journal(journal, allow_live=True)
        rec.finalize()


def test_cas_digest_rejects_path_traversal(tmp_path: Path):
    store = BlobStore(tmp_path / "blobs")
    with pytest.raises(BlobIntegrityError):
        require_digest("../outside")
    with pytest.raises(BlobIntegrityError):
        store.exists("../outside")
    with pytest.raises(BlobIntegrityError):
        store._path_for("not-a-digest")


def test_unsigned_receipt_refused(tmp_path: Path):
    path = tmp_path / "r.json"
    path.write_text(
        json.dumps({"format": "sage.verify.receipt.v1", "ok": True, "artifact_fingerprint": "a" * 64}),
        encoding="utf-8",
    )
    with pytest.raises(ChainIntegrityError, match="unsigned|missing HMAC"):
        verify_receipt(path)
    # Explicit escape hatch still works.
    assert verify_receipt(path, allow_unsigned=True)["ok"]


def test_policy_typo_fail_closed(tmp_path: Path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"format": "sage.verify.policy.v1", "require_pack_hmca": True}), encoding="utf-8")
    with pytest.raises(ChainIntegrityError, match="unknown fields"):
        load_policy(p)
    with pytest.raises(ChainIntegrityError, match="unsupported policy format"):
        load_policy({"format": "not-sage"})


def test_heal_capability_requires_source_bundle_hash(tmp_path: Path):
    with SageRecorder("h", register_trace=False) as rec:
        with rec.tool_call("t"):
            pass
        bundle = rec.finalize()
    cap = HealCapability.issue(bundle, heal_span_id=bundle.spans[0].span_id)
    assert cap.source_bundle_hash == bundle.audit.bundle_hash
    forged = cap.to_dict()
    forged["allowed_span_ids"] = list(forged["allowed_span_ids"]) + ["span_injected"]
    # Re-seal content hash without authority binding to original hash alone is not enough —
    # changing allowed_span_ids without recomputing seal fails; with recomputed seal still
    # fails source binding when applied to heal if hash differs. Here seal mismatch:
    with pytest.raises(SecurityDivergence, match="seal"):
        HealCapability.from_dict(forged)
    # Properly re-sealed forge still must carry source_bundle_hash; strip it:
    forged2 = cap.to_dict()
    from sage.heal_capability import capability_digest

    forged2["allowed_span_ids"] = ["span_injected"]
    forged2["seal"] = ""
    forged2["mac"] = ""
    forged2["seal"] = capability_digest(forged2)
    forged2["source_bundle_hash"] = ""
    with pytest.raises(SecurityDivergence, match="source_bundle_hash"):
        HealCapability.from_dict(forged2)


def test_heal_cascade_outside_capability_raises(tmp_path: Path):
    with SageRecorder("c", register_trace=False) as rec:
        with rec.retrieval("kb", inputs={"query": "q"}) as ret:
            ret.set_output(documents=[{"id": "d1"}])
            ret.set_data(query="q", documents=[{"id": "d1"}], source="kb")
        with rec.tool_call("update") as tool:
            tool.fail("schema drift")
        bundle = rec.finalize()
    heal_id = next(s.span_id for s in bundle.spans if s.type == "retrieval")
    # Capability allows cascade flag but only the primary span — tool must hard-fail.
    from sage.heal_capability import HealPatch

    cap = HealCapability.issue(bundle, heal_span_id=heal_id, extra_span_ids=[], allow_cascade=True)
    patch = HealPatch(
        capability=cap,
        primary_span_id=heal_id,
        mutations=[
            {
                "span_id": heal_id,
                "status": "ok",
                "error": None,
                "data": {"documents": [{"id": "d1", "fresh": True}], "query": "q"},
                "outputs": {"documents": [{"id": "d1", "fresh": True}]},
            }
        ],
    )
    with pytest.raises(SecurityDivergence, match="cascade"):
        apply_heal(
            bundle,
            span_id=heal_id,
            new_data={"documents": [{"id": "d1", "fresh": True}], "query": "q"},
            new_output={"documents": [{"id": "d1", "fresh": True}]},
            cascade=True,
            patch=patch,
        )


def test_events_redacted_before_hash(tmp_path: Path):
    with SageRecorder("e", blob_store=tmp_path / "blobs", register_trace=False) as rec:
        with rec.tool_call("t") as tool:
            tool.add_event("leak", api_key="sk-eventsecret99", body="Z" * 1500)
        bundle = rec.finalize()
    dumped = json.dumps(bundle.spans[0].to_dict())
    assert "sk-eventsecret99" not in dumped
    # Secret keys redact; large event payloads may CAS-offload.
    assert "[REDACTED]" in dumped or "$sage_blob" in dumped


def test_safe_tar_blocks_traversal(tmp_path: Path):
    evil = tmp_path / "evil.tar.gz"
    with tarfile.open(evil, "w:gz") as tar:
        info = tarfile.TarInfo(name="../escape.txt")
        data = b"pwn"
        info.size = len(data)
        import io

        tar.addfile(info, io.BytesIO(data))
    with tarfile.open(evil, "r:gz") as tar:
        with pytest.raises(ChainIntegrityError, match="traversal"):
            safe_extract_tar(tar, tmp_path / "out")


def test_pack_roundtrip_still_works(tmp_path: Path):
    with SageRecorder("p", blob_store=tmp_path / "b", register_trace=False) as rec:
        with rec.tool_call("t", inputs={"api_key": "sk-abc12345zz", "body": "Q" * 2048}):
            pass
        path = rec.export(tmp_path / "i.sage.json")
    pack = pack_artifact(path, tmp_path / "p.sage.tar.gz", hmac_key="k")
    report = verify_artifact(pack, hmac_key="k", check_witness=True, witness_key="k")
    assert report["ok"]
    # Signed receipt required path
    from sage.receipt import write_receipt

    rp = write_receipt(report, tmp_path / "r.json", hmac_key="k")
    assert verify_receipt(rp, hmac_key="k")["mac_verified"]
