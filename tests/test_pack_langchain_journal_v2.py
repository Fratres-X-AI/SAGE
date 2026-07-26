from __future__ import annotations

import json
from uuid import uuid4

import pytest

from sage.adapters.langchain_callback import SageLangChainCallback
from sage.bundle_io import load_bundle
from sage.errors import ChainIntegrityError
from sage.journal import CHAIN_JSONL, MANIFEST_NAME, SPANS_JSONL, compute_manifest_seal, verify_manifest_seal
from sage.pack import pack_artifact, unpack_artifact
from sage.recorder import SageRecorder


def test_live_journal_redacts_secrets_and_writes_chain(tmp_path):
    journal = tmp_path / "j"
    with SageRecorder(
        "sec",
        blob_store=tmp_path / "blobs",
        journal_dir=journal,
        register_trace=False,
    ) as rec:
        with rec.tool_call("auth", inputs={"api_key": "sk-supersecret-value", "q": "x"}) as tool:
            tool.set_output(token="abc123token", result="ok")
        raw = (journal / SPANS_JSONL).read_text(encoding="utf-8")
        assert "sk-supersecret-value" not in raw
        assert "[REDACTED]" in raw
        chain_lines = (journal / CHAIN_JSONL).read_text(encoding="utf-8").strip().splitlines()
        assert len(chain_lines) == 1
        link = json.loads(chain_lines[0])
        assert link["prev_hash"] == "0" * 64
        assert len(link["hash"]) == 64


def test_sealed_manifest_seal_roundtrip(tmp_path):
    with SageRecorder("seal", blob_store=tmp_path / "b", register_trace=False) as rec:
        with rec.tool_call("t", inputs={"x": 1}) as tool:
            tool.set_output(ok=True)
        bundle = rec.finalize()
    root = tmp_path / "journal"
    from sage.journal import save_journal

    save_journal(bundle, root)
    manifest = json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))
    assert manifest.get("manifest_seal")
    verify_manifest_seal(manifest)
    loaded = load_bundle(root, verify=True, rehydrate=False)
    assert loaded.audit.bundle_hash == bundle.audit.bundle_hash

    manifest["manifest_seal"] = "0" * 64
    (root / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises((ChainIntegrityError, Exception)):
        load_bundle(root, verify=True, rehydrate=False)


def test_pack_unpack_roundtrip_with_blobs(tmp_path):
    big = "B" * 2048
    with SageRecorder("pack", blob_store=tmp_path / "blobs", register_trace=False) as rec:
        with rec.tool_call("echo", inputs={"body": big}) as tool:
            tool.set_output(echo="ok")
        path = rec.export(tmp_path / "incident.sage.json")
    archive = pack_artifact(path, tmp_path / "out")
    assert archive.exists()
    dest = tmp_path / "unpacked"
    journal = unpack_artifact(archive, dest)
    loaded = load_bundle(journal, verify=True, rehydrate=True)
    assert big in json.dumps(loaded.spans[0].inputs) or big in json.dumps(loaded.spans[0].data)


def test_langchain_callback_records_llm_and_tool(tmp_path):
    with SageLangChainCallback(trace_id="lc-1", journal_dir=str(tmp_path / "lcj")) as cb:
        run = uuid4()
        cb.on_llm_start({"name": "ChatOpenAI"}, ["hello"], run_id=run)
        cb.on_llm_end(type("R", (), {"generations": [[type("G", (), {"text": "world"})()]]})(), run_id=run)
        tool_run = uuid4()
        cb.on_tool_start({"name": "search"}, "query", run_id=tool_run)
        cb.on_tool_end("docs", run_id=tool_run)
    bundle = cb.recorder.finalized_bundle()
    assert any(s.type == "llm" for s in bundle.spans)
    assert any(s.type == "tool" for s in bundle.spans)
    assert (tmp_path / "lcj" / CHAIN_JSONL).exists()


def test_compute_manifest_seal_stable():
    payload = {"a": 1, "b": {"c": 2}, "manifest_seal": "ignore-me"}
    s1 = compute_manifest_seal(payload)
    s2 = compute_manifest_seal({**payload, "manifest_seal": "other"})
    assert s1 == s2
    assert len(s1) == 64
