"""Recording must produce the same hashes for the same input, release to release.

The expected values below were captured from the 2.3.0rc1 recorder *before* the journal durability
modes and the recording fast path were added. Every durability mode must reproduce them exactly:
the bundle hash, the sealed manifest seal, the live chain tip, and the live journal lines.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

import sage.recorder as recorder_module
import sage.schema as schema_module
from sage.clock import set_clock
from sage.recorder import SageRecorder

EXPECTED_BUNDLE_HASH = "ff4d20c0aa2596ede810a3cc3331801b29ee83a95a4ea1b25f5ea5aca073b10d"
EXPECTED_MANIFEST_SEAL = "0475c99a5f150f68ed5223a12fd5e6b7fe33cce413616fd7691932a01f53f2e3"
EXPECTED_LIVE_CHAIN_TIP = "9806bc51555cb64d2d0c8ab0603441d56dc72dd6ffaf8511075f383853e02a0c"
EXPECTED_LIVE_SPANS_SHA256 = "aba59b9a87fe7a7bbae6094424e1da46602fc4e9ea1ae69371b280587650e187"
EXPECTED_LIVE_CHAIN_SHA256 = "640c4895831baafaf88c71a6342e5bf143e63244250f76239d4d8776479c49d7"
EXPECTED_MEMORY_ONLY_BUNDLE_HASH = "f269325f6e166210ca0ea78eb4f7aa46aa1d72aa790999ec2c937fe8b31a8273"


class _ManualClock:
    """Moves only when the workload calls `tick()`, so timestamps do not depend on how often the
    library reads the clock (or from which thread)."""

    def __init__(self) -> None:
        self._now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def now(self) -> datetime:
        return self._now

    def tick(self) -> None:
        self._now += timedelta(milliseconds=7)


_CLOCK = _ManualClock()


class _FixedMonotonic:
    def __init__(self) -> None:
        self._ns = 1_000_000

    def perf_counter_ns(self) -> int:
        self._ns += 1_000
        return self._ns


def _fixed_ids():
    """Sequential ids, counted per prefix so span ids do not depend on how many other ids are drawn."""
    counters: dict[str, int] = {}

    def fixed_id(prefix: str) -> str:
        counters[prefix] = counters.get(prefix, 0) + 1
        return f"{prefix}_{counters[prefix]:032x}"

    return fixed_id


@pytest.fixture
def deterministic(monkeypatch, tmp_path):
    fixed_id = _fixed_ids()
    monkeypatch.setattr(schema_module, "new_id", fixed_id)
    monkeypatch.setattr(recorder_module, "new_id", fixed_id)
    monkeypatch.setattr(recorder_module, "time", _FixedMonotonic())
    monkeypatch.chdir(tmp_path)  # relative blob store path keeps metadata identical everywhere
    global _CLOCK
    _CLOCK = _ManualClock()
    set_clock(_CLOCK)
    yield tmp_path
    set_clock(None)


def _record(rec: SageRecorder) -> None:
    """Fixed workload: nesting, redaction by key and by value, non-ASCII text, an offloaded payload,
    events, an error with failure context, a policy decision, and a handoff."""
    _CLOCK.tick()
    with rec.agent_step("triage", inputs={"goal": "résoudre le ticket ✓"}) as agent:
        _CLOCK.tick()
        agent.add_event("started", detail="Bearer abc.def.ghi")
        _CLOCK.tick()
        with rec.llm_call("plan") as llm:
            _CLOCK.tick()
            llm.set_model("test-model", temperature=0)
            _CLOCK.tick()
            llm.set_input(prompt="Summarise the ticket", api_key="sk-secretsecret1234")
            _CLOCK.tick()
            llm.set_output(text="call lookup_account")
            _CLOCK.tick()
            llm.set_usage(input_tokens=12, output_tokens=5)
        _CLOCK.tick()
        with rec.tool_call("lookup_account", inputs={"account": "A-17", "password": "hunter2"}) as tool:
            _CLOCK.tick()
            tool.set_output(ok=True, body="x" * 3000)
        _CLOCK.tick()
        with rec.retrieval("kb", inputs={"query": "refund policy"}) as ret:
            _CLOCK.tick()
            ret.set_output(documents=[{"id": "d1", "text": "naïve café"}, {"id": "d2", "text": "y" * 1500}])
        _CLOCK.tick()
        rec.policy_decision("refund-limit", decision="allow", inputs={"amount": 40}, reason="under limit")
        _CLOCK.tick()
        with rec.handoff("escalate", from_agent="triage", to_agent="billing", context_passed={"ticket": 7}):
            _CLOCK.tick()
            pass
        _CLOCK.tick()
        failed = rec.start_span("tool", "charge", inputs={"token": "sk-anothersecret5678", "amount": 40})
        _CLOCK.tick()
        # An explicit error record: a live traceback would embed this repository's line numbers.
        rec.end_span(
            failed.span_id,
            status="error",
            error={
                "type": "TimeoutError",
                "message": "gateway timeout for Bearer zzz.yyy",
                "stack": '  File "app/billing.py", line 10, in charge\n    post(key="sk-stacksecret12345")\n',
            },
        )
        _CLOCK.tick()
        rec.mark_failure(failed.span_id, note="charge timed out; key sk-notesecret99999")
        _CLOCK.tick()
        agent.set_output(result="failed")


def _lines_sha256(path) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def _run_with_journal(**recorder_kwargs):
    rec = SageRecorder(
        "hash-stability",
        trace_id="hash-stability-trace",
        run_id="hash-stability-run",
        blob_store="blobs",
        journal_dir="journal",
        register_trace=False,
        metadata={"customer": "synthetic", "authorization": "Bearer meta.secret"},
        **recorder_kwargs,
    )
    with rec:
        _record(rec)
        flush = getattr(rec, "flush_journal", None)
        if flush is not None:
            flush()
        from pathlib import Path

        live = {
            "spans": _lines_sha256(Path("journal") / "spans.jsonl"),
            "chain": _lines_sha256(Path("journal") / "chain.jsonl"),
            "tip": json.loads((Path("journal") / "manifest.sage.json").read_text(encoding="utf-8"))["chain_tip"],
        }
    from pathlib import Path

    manifest = json.loads((Path("journal") / "manifest.sage.json").read_text(encoding="utf-8"))
    return rec.finalize(), manifest, live


def _durability_params():
    return [{}, {"journal_durability": "span"}, {"journal_durability": "batch"}, {"journal_durability": "close"}]


@pytest.mark.parametrize("kwargs", _durability_params(), ids=["default", "span", "batch", "close"])
def test_journal_recording_hashes_are_unchanged(deterministic, kwargs):
    bundle, manifest, live = _run_with_journal(**kwargs)
    assert bundle.audit.bundle_hash == EXPECTED_BUNDLE_HASH
    assert manifest["manifest_seal"] == EXPECTED_MANIFEST_SEAL
    assert live["tip"] == EXPECTED_LIVE_CHAIN_TIP
    assert live["spans"] == EXPECTED_LIVE_SPANS_SHA256
    assert live["chain"] == EXPECTED_LIVE_CHAIN_SHA256


def test_memory_only_recording_hash_is_unchanged(deterministic):
    rec = SageRecorder(
        "hash-stability",
        trace_id="hash-stability-trace",
        run_id="hash-stability-run",
        blob_store="blobs",
        register_trace=False,
        metadata={"customer": "synthetic", "authorization": "Bearer meta.secret"},
    )
    with rec:
        _record(rec)
    assert rec.finalize().audit.bundle_hash == EXPECTED_MEMORY_ONLY_BUNDLE_HASH


if __name__ == "__main__":  # pragma: no cover - prints the values to pin
    import os
    import tempfile

    os.chdir(tempfile.mkdtemp(prefix="sage-hash-"))
    _fixed = _fixed_ids()
    schema_module.new_id = _fixed
    recorder_module.new_id = _fixed
    recorder_module.time = _FixedMonotonic()
    set_clock(_CLOCK)
    b, m, lv = _run_with_journal()
    print(json.dumps({"bundle_hash": b.audit.bundle_hash, "seal": m["manifest_seal"], **lv}, indent=2))
