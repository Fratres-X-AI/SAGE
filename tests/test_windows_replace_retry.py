"""replace_file / read_text_file wait out Windows sharing violations instead of failing."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from sage import locks


def _flaky(real, failures: int):
    calls = {"n": 0}

    def wrapper(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] <= failures:
            raise PermissionError(13, "The process cannot access the file")
        return real(*args, **kwargs)

    return wrapper, calls


def test_replace_retries_through_sharing_violations_on_windows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src, dst = tmp_path / "new", tmp_path / "manifest.sage.json"
    src.write_text("new", encoding="utf-8")
    dst.write_text("old", encoding="utf-8")
    flaky, calls = _flaky(os.replace, 3)
    monkeypatch.setattr(locks, "RETRY_SHARING_VIOLATIONS", True)
    monkeypatch.setattr(locks.os, "replace", flaky)
    locks.replace_file(src, dst)
    assert calls["n"] == 4
    assert dst.read_text(encoding="utf-8") == "new"


def test_read_retries_through_sharing_violations_on_windows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "manifest.sage.json"
    target.write_text("{}", encoding="utf-8")
    flaky, calls = _flaky(Path.read_text, 3)
    monkeypatch.setattr(locks, "RETRY_SHARING_VIOLATIONS", True)
    monkeypatch.setattr(Path, "read_text", flaky)
    assert locks.read_text_file(target) == "{}"
    assert calls["n"] == 4


def test_retry_gives_up_after_the_deadline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    flaky, _ = _flaky(os.replace, 10**9)
    monkeypatch.setattr(locks, "RETRY_SHARING_VIOLATIONS", True)
    monkeypatch.setattr(locks.os, "replace", flaky)
    with pytest.raises(PermissionError):
        locks.replace_file(tmp_path / "a", tmp_path / "b", retry_s=0.05)


def test_other_platforms_do_not_retry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    flaky, calls = _flaky(os.replace, 1)
    monkeypatch.setattr(locks, "RETRY_SHARING_VIOLATIONS", False)
    monkeypatch.setattr(locks.os, "replace", flaky)
    with pytest.raises(PermissionError):
        locks.replace_file(tmp_path / "a", tmp_path / "b")
    assert calls["n"] == 1
