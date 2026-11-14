#!/usr/bin/env python3
"""Build the single-file handoff verifier: ``dist/sage-verify-<version>.pyz``.

The archive vendors the pure-Python SAGE core and runs ``sage.handoff_verify``. It needs only a
Python 3.10+ interpreter: when ``cryptography`` is not installed it verifies Ed25519 signatures with
the bundled pure-Python verifier (``sage._ed25519_verify``). The build is reproducible: entries are
sorted and stamped with ``SOURCE_DATE_EPOCH`` (default: the last commit time, else 1980-01-01).

Usage:  python scripts/build_verifier.py [--out DIR]
Run:    python sage-verify-<version>.pyz <kit dir> --hmac-key-file <file> --public-key-file <file>
"""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "sage"
# Research, training, and UI code the verifier never imports.
EXCLUDE_DIRS = {"attribution", "synth", "__pycache__"}
EXCLUDE_FILES = {"tui_app.py"}
MAIN = """import sys

from sage.signing import enable_pure_python_verification

enable_pure_python_verification()

from sage.handoff_verify import main

raise SystemExit(main(sys.argv[1:], kit_required=True))
"""


def _epoch() -> int:
    if os.environ.get("SOURCE_DATE_EPOCH"):
        return int(os.environ["SOURCE_DATE_EPOCH"])
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "log", "-1", "--format=%ct"],
                             capture_output=True, text=True, check=True)
        return int(out.stdout.strip())
    except (OSError, subprocess.CalledProcessError, ValueError):
        return 315532800


def _members() -> list[tuple[str, bytes]]:
    members = [("__main__.py", MAIN.encode("utf-8"))]
    for path in sorted(SRC.rglob("*.py")):
        rel = path.relative_to(SRC)
        if EXCLUDE_DIRS.intersection(rel.parts[:-1]) or rel.name in EXCLUDE_FILES:
            continue
        members.append(("sage/" + rel.as_posix(), path.read_bytes().replace(b"\r\n", b"\n")))
    return sorted(members)


def build(out_dir: Path) -> Path:
    sys.path.insert(0, str(ROOT / "src"))
    from sage.version import __version__

    stamp = time.gmtime(max(_epoch(), 315532800))[:6]
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"sage-verify-{__version__}.pyz"
    tmp = target.with_suffix(".tmp")
    with open(tmp, "wb") as fh:
        fh.write(b"#!/usr/bin/env python3\n")
        with zipfile.ZipFile(fh, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for name, data in _members():
                info = zipfile.ZipInfo(name, date_time=stamp)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o644 << 16
                zf.writestr(info, data)
    os.replace(tmp, target)
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default=str(ROOT / "dist"))
    args = parser.parse_args(argv)
    target = build(Path(args.out))
    print(f"{target}  sha256={hashlib.sha256(target.read_bytes()).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
