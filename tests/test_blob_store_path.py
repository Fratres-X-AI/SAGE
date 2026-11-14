"""Sealed bundles never carry the producer's absolute blob store path."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from sage import SageRecorder
from sage.blobs import blob_store_hint
from sage.bundle_io import load_bundle
from sage.pack import pack_artifact, unpack_artifact
from sage.verify import verify_artifact

ROOT = Path(__file__).resolve().parents[1]
COMPAT = ROOT / "tests" / "fixtures" / "compat_v2_2_0"


def _record(tmp_path: Path, blob_root: Path, name: str = "paths") -> tuple[Path, Path]:
    rec = SageRecorder(title=name, trace_id=f"trace-{name}", journal_dir=tmp_path / f"{name}-j", blob_store=blob_root)
    with rec:
        with rec.llm_call("model", inputs={"prompt": "hello"}) as llm:
            llm.set_output(text="large output line " * 200)
    return rec.export(tmp_path / f"{name}.sage.json"), tmp_path / f"{name}-j"


def _absolute_strings(raw: str) -> list[str]:
    home = str(Path.home())
    return [needle for needle in (home, home.replace("\\", "/"), home.replace("\\", "\\\\")) if needle in raw]


def test_store_outside_working_directory_is_not_recorded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    bundle_path, journal = _record(tmp_path, tmp_path / "blobs")
    raw = bundle_path.read_text(encoding="utf-8")
    meta = json.loads(raw)["metadata"]
    assert "blob_store" not in meta
    assert str(tmp_path) not in raw and str(tmp_path).replace("\\", "\\\\") not in raw
    assert _absolute_strings(raw) == []
    manifest = (journal / "manifest.sage.json").read_text(encoding="utf-8")
    assert str(tmp_path).replace("\\", "\\\\") not in manifest and str(tmp_path) not in manifest


def test_store_inside_working_directory_is_recorded_relative(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    bundle_path, _journal = _record(tmp_path, tmp_path / ".sage" / "blobs")
    meta = json.loads(bundle_path.read_text(encoding="utf-8"))["metadata"]
    assert meta["blob_store"] == ".sage/blobs"
    assert blob_store_hint(tmp_path / "x" / "y") == "x/y"
    assert blob_store_hint(tmp_path.parent / "elsewhere") is None


def test_same_process_rehydrate_pack_and_verify_still_find_blobs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    bundle_path, journal = _record(tmp_path, tmp_path / "blobs")
    hydrated = load_bundle(bundle_path, verify=True, rehydrate=True)
    assert "large output line" in json.dumps(hydrated.to_dict())
    report = verify_artifact(bundle_path)
    assert report["ok"] is True
    pack = pack_artifact(journal, tmp_path / "e.sage.tar.gz", hmac_key=b"k" * 32)
    assert verify_artifact(pack, hmac_key=b"k" * 32)["ok"] is True


def test_cli_pack_needs_blob_root_for_an_outside_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    _bundle, journal = _record(tmp_path, tmp_path / "blobs")
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    base = [sys.executable, "-m", "sage.cli", "pack", str(journal), "--hmac-key", "k" * 32]
    without = subprocess.run([*base, "--out", str(tmp_path / "a.sage.tar.gz")],
                             capture_output=True, text=True, env=env, cwd=work, timeout=120)
    assert without.returncode == 1
    with_root = subprocess.run([*base, "--out", str(tmp_path / "b.sage.tar.gz"), "--blob-root", str(tmp_path / "blobs")],
                               capture_output=True, text=True, env=env, cwd=work, timeout=120)
    assert with_root.returncode == 0, with_root.stderr
    assert (tmp_path / "b.sage.tar.gz").exists()


def test_legacy_absolute_blob_store_is_still_honored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Bundles sealed by SAGE 2.2 carry an absolute path; reading them must keep working."""
    from sage.audit import attach_audit_chain

    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    bundle_path, _journal = _record(tmp_path, tmp_path / "blobs", name="legacy")
    bundle = load_bundle(bundle_path, verify=True)
    bundle.metadata["blob_store"] = str(tmp_path / "blobs")
    bundle.bundle_id = "bundle_legacy_not_registered"
    legacy = tmp_path / "legacy-abs.sage.json"
    legacy.write_text(json.dumps(attach_audit_chain(bundle).to_dict()), encoding="utf-8")
    hydrated = load_bundle(legacy, verify=True, rehydrate=True)
    assert "large output line" in json.dumps(hydrated.to_dict())


def test_compat_fixture_still_verifies() -> None:
    fixture = json.loads((COMPAT / "fixture.json").read_text(encoding="utf-8"))
    key = fixture["hmac_key"]
    report = verify_artifact(COMPAT / "evidence.sage.tar.gz", hmac_key=key)
    assert report["ok"] is True
    bundle_report = verify_artifact(COMPAT / "bundle.sage.json", blob_root=COMPAT / "blobs")
    assert bundle_report["ok"] is True


def test_unpacked_journal_round_trip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    _bundle, journal = _record(tmp_path, tmp_path / "blobs")
    pack = pack_artifact(journal, tmp_path / "e.sage.tar.gz", hmac_key=b"k" * 32)
    out = unpack_artifact(pack, tmp_path / "unpacked", hmac_key=b"k" * 32)
    assert load_bundle(out, verify=True).audit.bundle_hash


def test_unpack_does_not_record_the_receivers_absolute_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    _bundle, journal = _record(tmp_path, tmp_path / "blobs", name="unpackpath")
    pack = pack_artifact(journal, tmp_path / "u.sage.tar.gz", hmac_key=b"k" * 32)
    out = unpack_artifact(pack, tmp_path / "receiver", hmac_key=b"k" * 32)
    manifest = (out / "manifest.sage.json").read_text(encoding="utf-8")
    assert _absolute_strings(manifest) == []
    repacked = pack_artifact(out, tmp_path / "again.sage.tar.gz", hmac_key=b"k" * 32)
    assert verify_artifact(repacked, hmac_key=b"k" * 32)["ok"]


def test_verifying_a_pack_does_not_hide_the_producers_blob_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    bundle, _journal = _record(tmp_path, tmp_path / "outside-blobs", name="reverify")
    first = pack_artifact(bundle, tmp_path / "first.sage.tar.gz", hmac_key=b"k" * 32)
    assert verify_artifact(first, hmac_key=b"k" * 32)["ok"]  # unpacks into a temporary store
    second = pack_artifact(bundle, tmp_path / "second.sage.tar.gz", hmac_key=b"k" * 32)
    assert verify_artifact(second, hmac_key=b"k" * 32)["ok"]
