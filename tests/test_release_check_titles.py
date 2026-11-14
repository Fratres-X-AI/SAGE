"""release_check.py flags document titles stamped with an old version."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("release_check", ROOT / "scripts" / "release_check.py")
rc = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(rc)


def test_stale_stamp_is_reported_and_current_or_unstamped_pass(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "OLD.md").write_text("# Threat Model (v2.0)\n", encoding="utf-8")
    (tmp_path / "docs" / "RUN.md").write_text("# Runbook (v2.3)\n", encoding="utf-8")
    (tmp_path / "MIGRATION.md").write_text("# Migrating to SAGE 2.0\n", encoding="utf-8")
    (tmp_path / "EMPTY.md").write_text("", encoding="utf-8")
    assert rc.stale_titles(tmp_path, "2.3") == ["OLD.md title says v2.0; current is v2.3"]


def test_repository_has_no_stale_titles() -> None:
    from sage.version import __version__

    assert rc.stale_titles(ROOT, ".".join(__version__.split(".")[0:2])) == []
