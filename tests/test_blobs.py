from __future__ import annotations

import json

from sage.audit import require_verified, verify_audit_chain
from sage.blobs import BLOB_MARKER, BlobStore, is_blob_ref
from sage.bundle_io import load_bundle, save_bundle
from sage.diff import diff_bundles
from sage.recorder import SageRecorder
from sage.replay import pure_recorded_replay


def test_cas_offloads_large_payloads_and_dedupes(tmp_path):
    blob_root = tmp_path / "blobs"
    big = "x" * 2048
    with SageRecorder("cas", blob_store=blob_root) as rec:
        with rec.tool_call("echo-a", inputs={"body": big}) as tool:
            tool.set_output(echo="ok")
        with rec.tool_call("echo-b", inputs={"body": big}) as tool:
            tool.set_output(echo="ok")

    path = rec.export(tmp_path / "incident.sage.json")
    compact = json.loads(path.read_text(encoding="utf-8"))
    require_verified(load_bundle(path, rehydrate=False))

    # Large strings replaced with blob refs in primary JSON.
    tool_a = next(s for s in compact["spans"] if s["name"] == "echo-a")
    assert is_blob_ref(tool_a["inputs"]["body"])
    digest = tool_a["inputs"]["body"][BLOB_MARKER]
    assert (blob_root / digest).exists()

    # Same payload written once (dedupe across spans).
    files = [p for p in blob_root.iterdir() if p.is_file()]
    assert len(files) == 1

    # Rehydrate for replay/diff consumers.
    hydrated = load_bundle(path, verify=True, rehydrate=True, blob_store=blob_root)
    tool_h = next(s for s in hydrated.spans if s.name == "echo-a")
    assert tool_h.inputs["body"] == big

    replay = pure_recorded_replay(hydrated)
    assert replay.ok
    assert verify_audit_chain(load_bundle(path, rehydrate=False))


def test_inspect_replay_diff_rehydrate_compat(tmp_path):
    blob_root = tmp_path / "blobs"
    doc = "retrieved-document-" + ("y" * 1500)
    with SageRecorder("compat", blob_store=blob_root) as rec:
        with rec.retrieval("kb", inputs={"query": "q"}) as span:
            span.set_output(documents=[{"text": doc}])
            span.set_data(query="q", documents=[{"text": doc}], source="kb")

    path = rec.export(tmp_path / "a.sage.json")
    left = load_bundle(path, verify=True, rehydrate=True, blob_store=blob_root)
    right = load_bundle(path, verify=True, rehydrate=True, blob_store=blob_root)
    assert diff_bundles(left, right).ok
    assert pure_recorded_replay(left).ok

    # Saving compact form remains portable.
    compact = load_bundle(path, verify=True, rehydrate=False)
    out = tmp_path / "copy.sage.json"
    save_bundle(compact, out)
    assert load_bundle(out, verify=True, rehydrate=False).audit.bundle_hash == compact.audit.bundle_hash


def test_dropin_trace_id_recorder(tmp_path):
    with SageRecorder(trace_id="user-123") as recorder:
        with recorder.agent_step("run"):
            pass
    assert recorder.bundle.bundle_id == "user-123"
    path = recorder.export(tmp_path / "t.sage.json")
    bundle = load_bundle(path, verify=True)
    assert bundle.bundle_id == "user-123"
