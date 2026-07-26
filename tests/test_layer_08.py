from __future__ import annotations

import json
import tarfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sage.clock import FakeClock, set_clock, utc_now
from sage.errors import ChainIntegrityError
from sage.journal import load_journal, save_journal
from sage.merkle import chain_merkle_root, merkle_root
from sage.pack import pack_artifact, unpack_artifact
from sage.recorder import SageRecorder
from sage.schema import utc_now as schema_utc_now


def test_merkle_root_deterministic():
    assert merkle_root([]) == "0" * 64
    a = merkle_root(["aa" * 32, "bb" * 32])
    b = merkle_root(["aa" * 32, "bb" * 32])
    assert a == b
    assert a != merkle_root(["aa" * 32, "cc" * 32])


def test_manifest_merkle_root_roundtrip(tmp_path: Path):
    with SageRecorder(title="m", journal_dir=tmp_path / "j") as rec:
        with rec.span("tool", "t"):
            pass
        bundle = rec.finalize()
    paths = save_journal(bundle, tmp_path / "sealed")
    manifest = json.loads(paths.manifest.read_text(encoding="utf-8"))
    assert manifest.get("merkle_root")
    assert manifest["merkle_root"] == chain_merkle_root(bundle.audit.chain)
    loaded = load_journal(tmp_path / "sealed", verify=True)
    assert loaded.audit.bundle_hash == bundle.audit.bundle_hash


def test_merkle_tamper_fail_closed(tmp_path: Path):
    with SageRecorder(title="m2") as rec:
        with rec.span("tool", "t"):
            pass
        with rec.span("llm", "l"):
            pass
        bundle = rec.finalize()
    paths = save_journal(bundle, tmp_path / "j")
    manifest = json.loads(paths.manifest.read_text(encoding="utf-8"))
    manifest["merkle_root"] = "f" * 64
    # Re-seal with tampered merkle so seal passes but merkle check fails.
    from sage.journal import compute_manifest_seal

    del manifest["manifest_seal"]
    manifest["manifest_seal"] = compute_manifest_seal(manifest)
    paths.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    with pytest.raises(ChainIntegrityError, match="merkle_root"):
        load_journal(tmp_path / "j", verify=True)


def test_pack_hmac_attestation(tmp_path: Path):
    with SageRecorder(title="p", journal_dir=tmp_path / "live") as rec:
        with rec.span("tool", "t", inputs={"x": "y"}):
            pass
        bundle = rec.finalize()
    journal = tmp_path / "journal"
    save_journal(bundle, journal)
    pack = pack_artifact(journal, tmp_path / "a.sage.tar.gz", hmac_key="secret-key")
    out = unpack_artifact(pack, tmp_path / "out", hmac_key="secret-key")
    assert (out / "manifest.sage.json").exists() or (out / "spans.jsonl").exists()

    # Wrong key fails.
    with pytest.raises(ChainIntegrityError, match="attestation"):
        unpack_artifact(pack, tmp_path / "bad", hmac_key="wrong-key")


def test_pack_content_digest_tamper(tmp_path: Path):
    with SageRecorder(title="p2") as rec:
        with rec.span("tool", "t"):
            pass
        bundle = rec.finalize()
    journal = tmp_path / "journal"
    save_journal(bundle, journal)
    pack = pack_artifact(journal, tmp_path / "b.sage.tar.gz")
    # Mutate blob inside archive.
    with tarfile.open(pack, "r:gz") as tar:
        try:
            tar.extractall(tmp_path / "extracted", filter="data")
        except TypeError:
            tar.extractall(tmp_path / "extracted")
    art = tmp_path / "extracted" / "sage_artifact"
    span_file = art / "journal" / "spans.jsonl"
    span_file.write_bytes(span_file.read_bytes() + b"\n")
    # Rebuild tar
    tampered = tmp_path / "tampered.sage.tar.gz"
    with tarfile.open(tampered, "w:gz") as tar:
        tar.add(art, arcname="sage_artifact")
    with pytest.raises(ChainIntegrityError, match="content_digest"):
        unpack_artifact(tampered, tmp_path / "out2")


def test_fake_clock_deterministic():
    clock = FakeClock(datetime(2024, 6, 1, tzinfo=timezone.utc), step_ms=10)
    set_clock(clock)
    try:
        t1 = utc_now()
        clock.tick()
        t2 = schema_utc_now()
        assert t1.startswith("2024-06-01")
        assert t1 != t2
        assert t2 > t1
    finally:
        set_clock(None)


def test_run_wrapper_crew_shaped(tmp_path: Path):
    from sage.adapters.run_wrapper import crewai_kickoff

    class Crew:
        def kickoff(self, prompt: str) -> str:
            return f"ok:{prompt}"

    crew = Crew()
    with crewai_kickoff(crew, journal_dir=tmp_path / "j") as rec:
        result = crew.kickoff("hello")
        assert result == "ok:hello"
        bundle = rec.finalize()
    assert any(s.name == "kickoff" for s in bundle.spans)
    # Method restored
    assert crew.kickoff("x") == "ok:x"
