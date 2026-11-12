"""Canary-based redaction coverage across every field that can hold captured text."""

from __future__ import annotations

import gzip
import io
import json
import tarfile
from pathlib import Path

import pytest

from sage import SageRecorder, redact_bundle
from sage.schema import IncidentBundle, SageSpan, SpanError

BEARER_CANARY = "Bearer CANARYbearer0123456789"
SK_CANARY = "sk-CANARYsk0123456789abcdef"
CUSTOM_CANARY = "ACCT-CANARY-77881"
KEY_CANARY = "keyed-canary-value-9931"
CANARY_MARKERS = ("CANARYbearer", "CANARYsk", "ACCT-CANARY", "keyed-canary-value")

# Policy regexes are recorded in redaction_policy, so the custom rule must not spell the marker literally.
CUSTOM_POLICY = {"value_patterns": [r"ACCT-[C]ANARY-\d+", r"sk-[A-Za-z0-9_\-]{8,}", r"Bearer\s+[A-Za-z0-9_\-\.]+"]}


def _assert_no_canary(blob: str, where: str) -> None:
    for marker in CANARY_MARKERS:
        assert marker not in blob, f"canary {marker!r} survived in {where}"


def _bundle_with_error_canaries() -> IncidentBundle:
    span = SageSpan(
        type="tool",
        name="lookup",
        trace_id="t1",
        end_time="2026-01-01T00:00:01Z",
        status="error",
        error=SpanError(
            type="AuthError",
            message=f"upstream rejected {BEARER_CANARY}",
            stack=f'File "app.py", line 12, in call\n  raise AuthError("{SK_CANARY}")',
        ),
        failure_context=f"retry with {SK_CANARY}",
        events=[{"name": "retry", "detail": f"header {BEARER_CANARY}"}],
        data={"success": False},
    )
    return IncidentBundle(title="b1", spans=[span], metadata={"note": f"seen {SK_CANARY}"})


def test_redact_bundle_scrubs_span_error_message_and_stack() -> None:
    red = redact_bundle(_bundle_with_error_canaries())
    _assert_no_canary(json.dumps(red.to_dict()), "redact_bundle output")
    span = red.spans[0]
    assert span.error is not None
    assert span.error.type == "AuthError"
    assert "upstream rejected" in span.error.message
    assert 'line 12' in (span.error.stack or "")
    assert "retry with" in (span.failure_context or "")


def _record_canary_run(tmp_path: Path, *, policy: dict | None = None) -> tuple[SageRecorder, Path]:
    journal = tmp_path / "journal"
    rec = SageRecorder(
        title="canary run",
        trace_id="canary-trace",
        journal_dir=journal,
        blob_store=tmp_path / "blobs",
        redaction_policy=policy or dict(CUSTOM_POLICY),
        metadata={"customer": "Fictional Co", "api_key": KEY_CANARY, "ticket": f"ref {CUSTOM_CANARY}"},
    )
    with rec:
        with rec.chain("support-flow", inputs={"question": "Where is my order 42?"}) as chain:
            with rec.llm_call(
                "model",
                inputs={"messages": [{"role": "user", "content": f"auth {BEARER_CANARY}"}], "password": KEY_CANARY},
                data={"model": "deterministic-test-model"},
            ) as llm:
                llm.set_output(text="Order 42 shipped.")
                llm.add_event("note", text=f"saw {SK_CANARY}")
            try:
                with rec.tool_call("account_lookup", inputs={"account": CUSTOM_CANARY, "nested": [{"token": KEY_CANARY}]}):
                    raise PermissionError(f"denied for {BEARER_CANARY} acct {CUSTOM_CANARY}")
            except PermissionError:
                pass
            big = ("order history line for Fictional Co " * 80) + SK_CANARY
            with rec.retrieval("history", inputs={"query": "orders"}) as r:
                r.span.outputs = {"documents": [big]}
            chain.span.outputs = {"answer": "Order 42 shipped."}
        tool_span = next(s for s in rec.bundle.spans if s.name == "account_lookup")
        rec.mark_failure(tool_span.span_id, note=f"tool failed with {BEARER_CANARY}")
    return rec, journal


def _read_tree(root: Path) -> str:
    parts = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            raw = path.read_bytes()
            try:
                raw = gzip.decompress(raw)
            except OSError:
                pass
            parts.append(raw.decode("utf-8", errors="replace"))
    return "\n".join(parts)


def test_recorder_journal_blobs_and_export_have_no_canaries(tmp_path: Path) -> None:
    rec, journal = _record_canary_run(tmp_path)
    out = rec.export(tmp_path / "bundle.json")
    _assert_no_canary(out.read_text(encoding="utf-8"), "exported bundle")
    _assert_no_canary(_read_tree(journal), "journal directory")
    _assert_no_canary(_read_tree(tmp_path / "blobs"), "blob store")
    for span in rec.bundle.spans:
        _assert_no_canary(json.dumps(span.to_dict()), f"in-memory span {span.name}")


def test_pack_contents_have_no_canaries(tmp_path: Path) -> None:
    from sage.pack import pack_artifact

    rec, journal = _record_canary_run(tmp_path)
    packed = pack_artifact(journal, tmp_path / "evidence.sage.tar.gz", blob_store=tmp_path / "blobs", hmac_key=b"k" * 32)
    data = Path(packed).read_bytes()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
        texts = []
        for member in tar.getmembers():
            if member.isfile():
                raw = tar.extractfile(member).read()  # type: ignore[union-attr]
                try:
                    raw = gzip.decompress(raw)
                except OSError:
                    pass
                texts.append(raw.decode("utf-8", errors="replace"))
    _assert_no_canary("\n".join(texts), "decompressed pack")


def test_redaction_keeps_useful_nonsecret_context(tmp_path: Path) -> None:
    rec, _journal = _record_canary_run(tmp_path)
    bundle = rec.finalize()
    blob = json.dumps(bundle.to_dict())
    assert "Where is my order 42?" in blob
    assert "Fictional Co" in blob
    assert "deterministic-test-model" in blob
    tool = next(s for s in bundle.spans if s.name == "account_lookup")
    assert tool.error is not None
    assert tool.error.type == "PermissionError"
    assert "denied for" in tool.error.message
    assert tool.status == "error"
    assert "tool failed with" in (tool.failure_context or "")


def test_token_count_keys_are_not_over_redacted() -> None:
    span = SageSpan(
        type="llm",
        name="m",
        trace_id="t",
        end_time="2026-01-01T00:00:01Z",
        data={"model": "x", "usage": {"input_tokens": 12, "total_tokens": 20}},
    )
    red = redact_bundle(IncidentBundle(title="t", spans=[span]))
    assert red.spans[0].data["usage"] == {"input_tokens": 12, "total_tokens": 20}


def test_exception_stack_keeps_location_without_absolute_paths() -> None:
    try:
        raise ValueError("boom")
    except ValueError as exc:
        err = SpanError.from_value(exc)
    assert err is not None and err.type == "ValueError"
    assert "tests/test_redaction_canaries.py" in (err.stack or "")
    assert str(Path(__file__).resolve().parents[1]) not in (err.stack or "")


@pytest.mark.parametrize("field", ["message", "stack"])
def test_live_span_error_is_sanitized_before_journal(tmp_path: Path, field: str) -> None:
    rec = SageRecorder(title="live", trace_id="live-trace", journal_dir=tmp_path / "j", blob_store=tmp_path / "b")
    with rec:
        span = rec.start_span("tool", "t")
        err = {"type": "E", "message": "m", "stack": "s"}
        err[field] = f"oops {BEARER_CANARY}"
        rec.end_span(span.span_id, status="error", error=err)
        _assert_no_canary((tmp_path / "j").joinpath("spans.jsonl").read_text(encoding="utf-8")
                          if (tmp_path / "j" / "spans.jsonl").exists() else _read_tree(tmp_path / "j"),
                          "live journal")
