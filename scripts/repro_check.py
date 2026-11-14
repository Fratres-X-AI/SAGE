#!/usr/bin/env python3
"""Reproducible-build check: build HEAD twice from two separate clean exports and compare hashes.

SOURCE_DATE_EPOCH is taken from the HEAD commit time so archive timestamps are deterministic.
Exit 0 when every artifact (wheel and sdist) is byte-identical across both builds.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()


def _export(ref: str, dest: Path) -> None:
    raw = subprocess.run(["git", "archive", "--format=tar", ref], cwd=ROOT, check=True, capture_output=True).stdout
    with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
        tar.extractall(dest, filter="data")


def _build(src: Path, out: Path, epoch: str) -> dict[str, str]:
    env = dict(os.environ, SOURCE_DATE_EPOCH=epoch)
    proc = subprocess.run([sys.executable, "-m", "build", "--outdir", str(out), str(src)],
                          env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout[-3000:] + proc.stderr[-3000:], file=sys.stderr)
        raise SystemExit(2)
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.iterdir()) if p.is_file()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", default="HEAD")
    parser.add_argument("--out", default=None, help="write the JSON report here")
    args = parser.parse_args(argv)
    epoch = _git("log", "-1", "--format=%ct", args.ref)
    with tempfile.TemporaryDirectory(prefix="sage-repro-") as tmp:
        builds = []
        for name in ("a", "b"):
            src = Path(tmp) / f"src-{name}"
            src.mkdir()
            _export(args.ref, src)
            builds.append(_build(src, Path(tmp) / f"dist-{name}", epoch))
    a, b = builds
    report = {
        "ref": _git("rev-parse", args.ref),
        "source_date_epoch": epoch,
        "artifacts": a,
        "identical": a == b and bool(a),
        "mismatched": sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k)),
    }
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if report["identical"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
