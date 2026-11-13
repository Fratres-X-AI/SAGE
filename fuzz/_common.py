"""Shared contract for the SAGE fuzz harnesses.

The verifier is fed hostile bytes. It may accept them or reject them with a SageError (exit 1 or 2
in the CLI). Any other exception is a crash: a hostile input reached an untyped failure path.
"""

from __future__ import annotations

import atexit
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
VECTORS = REPO / "tests" / "vectors"
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

from sage.errors import SageError  # noqa: E402

HMAC_KEY = (VECTORS / "keys" / "hmac.key").read_text(encoding="utf-8").strip()
PUBLIC_KEY = (VECTORS / "keys" / "ed25519.public.txt").read_text(encoding="utf-8").strip()
SCRATCH = Path(tempfile.mkdtemp(prefix="sage-fuzz-"))
atexit.register(shutil.rmtree, SCRATCH, ignore_errors=True)


def expect_typed_rejection(fn) -> None:
    try:
        fn()
    except SageError:
        pass


def run(test_one_input) -> None:
    import atheris

    atheris.instrument_all()
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
