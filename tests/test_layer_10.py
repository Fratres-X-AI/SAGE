from __future__ import annotations

import json
from pathlib import Path

import pytest

from sage.cli import build_parser
from sage.errors import ChainIntegrityError
from sage.journal import save_journal
from sage.pack import pack_artifact, unpack_artifact
from sage.recorder import SageRecorder
from sage.verify import detect_artifact_kind, verify_artifact, verify_blob_inventory
from sage.witness import WITNESS_JSONL, append_witness, verify_witness_log


def test_detect_artifact_kinds(tmp_path: Path):
    with SageRecorder("k", register_trace=False) as rec:
        with rec.tool_call("t"):
            pass
        path = rec.export(tmp_path / "a.sage.json")
    journal = tmp_path / "j"
    save_journal(rec.finalize(), journal)
    pack = pack_artifact(path, tmp_path / "p.sage.tar.gz", write_witness=False)
    assert detect_artifact_kind(path) == "bundle"
    assert detect_artifact_kind(journal) == "journal"
    assert detect_artifact_kind(pack) == "pack"


def test_verify_bundle_and_blob_inventory(tmp_path: Path):
    big = "Z" * 2048
    with SageRecorder("b", blob_store=tmp_path / "blobs", register_trace=False) as rec:
        with rec.tool_call("echo", inputs={"body": big}):
            pass
        path = rec.export(tmp_path / "inc.sage.json")
        bundle = rec.finalize()
    report = verify_artifact(path, require_sealed=True, blob_root=tmp_path / "blobs")
    assert report["ok"]
    assert report["blobs"]["blob_count"] >= 1
    inv = verify_blob_inventory(bundle, blob_root=tmp_path / "blobs")
    assert inv["blob_merkle"]


def test_verify_pack_enriched_meta_and_witness(tmp_path: Path):
    with SageRecorder("p", blob_store=tmp_path / "blobs", register_trace=False) as rec:
        with rec.tool_call("t", inputs={"api_key": "sk-abc12345", "body": "x" * 1500}):
            pass
        path = rec.export(tmp_path / "inc.sage.json")
    pack = pack_artifact(path, tmp_path / "ship.sage.tar.gz", hmac_key="k1", actor="ci")
    report = verify_artifact(
        pack,
        require_sealed=True,
        hmac_key="k1",
        check_witness=True,
        witness_key="k1",
    )
    assert report["ok"]
    assert report["kind"] == "pack"
    assert report["pack"]["format"] in {"sage.pack.v1", "sage.pack.v2"}
    assert report["pack"]["blob_merkle"]
    assert report["pack"]["redaction_summary"]["redaction_count"] >= 1
    assert report["witness"]["records"] >= 1


def test_witness_chain_tamper_fail_closed(tmp_path: Path):
    root = tmp_path / "ev"
    append_witness(root, action="seal", bundle_hash="a" * 64, chain_tip="b" * 64, hmac_key="w")
    append_witness(root, action="ship", bundle_hash="a" * 64, chain_tip="b" * 64, hmac_key="w")
    verify_witness_log(root, hmac_key="w", expect_bundle_hash="a" * 64)
    lines = (root / WITNESS_JSONL).read_text(encoding="utf-8").splitlines()
    bad = json.loads(lines[1])
    bad["action"] = "forged"
    lines[1] = json.dumps(bad, sort_keys=True, separators=(",", ":"))
    (root / WITNESS_JSONL).write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(ChainIntegrityError):
        verify_witness_log(root, hmac_key="w")


def test_cli_verify_exit_zero(tmp_path: Path):
    with SageRecorder("cli", register_trace=False) as rec:
        with rec.tool_call("t"):
            pass
        path = rec.export(tmp_path / "x.sage.json")
    parser = build_parser()
    args = parser.parse_args(["verify", str(path), "--skip-blobs"])
    assert args.func(args) == 0


def test_missing_blob_fail_closed(tmp_path: Path):
    big = "Q" * 2048
    with SageRecorder("m", blob_store=tmp_path / "blobs", register_trace=False) as rec:
        with rec.tool_call("echo", inputs={"body": big}):
            pass
        path = rec.export(tmp_path / "m.sage.json")
    # Point verify at empty store
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ChainIntegrityError, match="missing CAS"):
        verify_artifact(path, blob_root=empty)


def test_unpack_preserves_pack_witness(tmp_path: Path):
    with SageRecorder("u", register_trace=False) as rec:
        with rec.tool_call("t"):
            pass
        path = rec.export(tmp_path / "u.sage.json")
    pack = pack_artifact(path, tmp_path / "u.sage.tar.gz", hmac_key="secret")
    journal = unpack_artifact(pack, tmp_path / "out", hmac_key="secret")
    assert (journal / WITNESS_JSONL).exists()
    w = verify_witness_log(journal, hmac_key="secret")
    assert w["records"] >= 2  # pack + unpack
