"""Artifacts sealed by earlier releases must keep verifying, and verification must not rewrite them."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sage.errors import ChainIntegrityError
from sage.verify import verify_artifact

FIXTURES = Path(__file__).parent / "fixtures"
COMPAT_DIRS = sorted(p for p in FIXTURES.glob("compat_*") if (p / "fixture.json").exists())


def _digest_tree(root: Path) -> dict[str, str]:
    return {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


@pytest.mark.parametrize("fixture_dir", COMPAT_DIRS, ids=[p.name for p in COMPAT_DIRS])
def test_old_bundle_and_pack_still_verify(fixture_dir: Path) -> None:
    meta = json.loads((fixture_dir / "fixture.json").read_text(encoding="utf-8"))
    before = _digest_tree(fixture_dir)

    bundle_report = verify_artifact(fixture_dir / meta["bundle"], blob_root=fixture_dir / "blobs")
    assert bundle_report["ok"] is True

    pack_report = verify_artifact(fixture_dir / meta["pack"], hmac_key=meta["hmac_key"])
    assert pack_report["ok"] is True
    assert pack_report["pack_hmac_verified"] is True
    assert pack_report["bundle_hash"] == bundle_report["bundle_hash"]

    assert _digest_tree(fixture_dir) == before


@pytest.mark.parametrize("fixture_dir", COMPAT_DIRS, ids=[p.name for p in COMPAT_DIRS])
def test_old_pack_rejects_wrong_hmac(fixture_dir: Path) -> None:
    meta = json.loads((fixture_dir / "fixture.json").read_text(encoding="utf-8"))
    with pytest.raises(ChainIntegrityError):
        verify_artifact(fixture_dir / meta["pack"], hmac_key="wrong-key")


def test_compat_fixtures_present() -> None:
    assert COMPAT_DIRS, "expected at least one sealed compatibility fixture"
