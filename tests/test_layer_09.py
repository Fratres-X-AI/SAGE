from __future__ import annotations

import json
from pathlib import Path

import pytest

from sage.cli import build_parser
from sage.errors import ChainIntegrityError
from sage.journal import (
    MANIFEST_NAME,
    MANIFEST_WAL,
    recover_manifest_from_wal,
    save_journal,
    verify_journal,
)
from sage.recorder import SageRecorder


def test_sanitize_on_close_strips_secrets_from_memory(tmp_path: Path):
    with SageRecorder(
        "mem",
        blob_store=tmp_path / "blobs",
        register_trace=False,
        sanitize_on_close=True,
    ) as rec:
        with rec.tool_call("auth", inputs={"api_key": "sk-inmemory-secret", "q": "x"}) as tool:
            tool.set_output(token="secret-token-value", result="ok")
        span = rec.bundle.spans[0]
        dumped = json.dumps(span.to_dict())
        assert "sk-inmemory-secret" not in dumped
        assert "secret-token-value" not in dumped
        assert "[REDACTED]" in dumped
        bundle = rec.finalize()
    assert bundle.audit.bundle_hash


def test_manifest_wal_recover(tmp_path: Path):
    journal = tmp_path / "j"
    with SageRecorder("wal", journal_dir=journal, register_trace=False) as rec:
        with rec.tool_call("t", inputs={"x": 1}):
            pass
        assert (journal / MANIFEST_WAL).exists()
        wal_lines = (journal / MANIFEST_WAL).read_text(encoding="utf-8").strip().splitlines()
        assert len(wal_lines) >= 2  # enter + span close
        tip_before = json.loads((journal / MANIFEST_NAME).read_text(encoding="utf-8"))["chain_tip"]
        (journal / MANIFEST_NAME).unlink()
        restored = recover_manifest_from_wal(journal)
        assert restored is not None
        assert restored["chain_tip"] == tip_before
        report = verify_journal(journal, allow_live=True)
        assert report["ok"] and report["live"]
        rec.finalize()


def test_verify_journal_sealed_and_cli(tmp_path: Path):
    with SageRecorder("v", register_trace=False) as rec:
        with rec.tool_call("t"):
            pass
        with rec.llm_call("l"):
            pass
        bundle = rec.finalize()
    root = tmp_path / "sealed"
    save_journal(bundle, root)
    report = verify_journal(root, allow_live=False)
    assert report["ok"]
    assert report["manifest_seal"]
    assert report["merkle_root"]
    assert report["span_count"] == 2

    parser = build_parser()
    args = parser.parse_args(["verify-journal", str(root), "--require-sealed"])
    assert args.func(args) == 0


def test_verify_journal_tip_mismatch_fail_closed(tmp_path: Path):
    with SageRecorder("bad", register_trace=False) as rec:
        with rec.tool_call("t"):
            pass
        bundle = rec.finalize()
    root = tmp_path / "sealed"
    save_journal(bundle, root)
    manifest = json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))
    manifest["chain_tip"] = "a" * 64
    from sage.journal import compute_manifest_seal

    del manifest["manifest_seal"]
    manifest["manifest_seal"] = compute_manifest_seal(manifest)
    (root / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    with pytest.raises(ChainIntegrityError, match="chain_tip"):
        verify_journal(root, allow_live=False)


def test_parent_hash_filled_from_chain_when_map_incomplete(tmp_path: Path):
    from sage.journal import append_live_span, prepare_span_for_disk
    from sage.schema import SageSpan

    journal = tmp_path / "j"
    journal.mkdir()
    parent = SageSpan(type="agent", name="parent", trace_id="t1", inputs={"a": 1})
    parent.finish()
    child = SageSpan(
        type="tool",
        name="child",
        parent_id=parent.span_id,
        trace_id="t1",
        inputs={"b": 2},
    )
    child.finish()
    _p_disk, p_link = append_live_span(
        journal,
        parent,
        index=0,
        prev_hash="0" * 64,
        blob_store=None,
        content_by_id={},
    )
    # Deliberately omit parent from content map — must resolve from chain.jsonl
    c_disk, c_link = append_live_span(
        journal,
        child,
        index=1,
        prev_hash=p_link["hash"],
        blob_store=None,
        content_by_id={},
        disk_span=prepare_span_for_disk(child),
    )
    assert c_link["parent_content_hash"] == p_link["content_hash"]
    assert c_disk.parent_id == parent.span_id
