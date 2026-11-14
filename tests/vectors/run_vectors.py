"""Check the reference implementation against every conformance vector.

    python tests/vectors/run_vectors.py        exit 0 when every vector matches its expected outcome

A vector matches when the artifact is accepted (`expect: accept`) or rejected with exactly the
expected `error_type` and exit code. See docs/spec/FORMAT.md section 11.2.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXIT_FOR = {"FaultRecoveryError": 2}


def _key(root: Path, manifest: dict, value) -> str | None:
    if value is True:
        return (root / manifest["hmac_key_file"]).read_text(encoding="utf-8").strip()
    return value or None


def _pin(root: Path, manifest: dict, value) -> str | None:
    if value is True:
        return (root / manifest["public_key_file"]).read_text(encoding="utf-8").strip()
    return value or None


def _check_artifact(root: Path, manifest: dict, vec: dict) -> tuple[str | None, int]:
    from sage.errors import SageError
    from sage.verify import verify_artifact

    key = _key(root, manifest, vec.get("hmac_key"))
    pin = _pin(root, manifest, vec.get("public_key"))
    blob_root = vec.get("blob_root")
    try:
        verify_artifact(
            root / vec["artifact"],
            hmac_key=key,
            witness_key=key,
            public_key=pin,
            policy=vec.get("policy"),
            blob_root=str(root / blob_root) if blob_root else None,
        )
    except SageError as exc:
        name = type(exc).__name__
        return name, EXIT_FOR.get(name, 1)
    return None, 0


def _check_kit(root: Path, manifest: dict, vec: dict) -> tuple[str | None, int]:
    from sage import handoff_verify

    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = handoff_verify.main([
            str(root / vec["artifact"]),
            "--hmac-key-file", str(root / manifest["hmac_key_file"]),
            "--public-key-file", str(root / manifest["public_key_file"]),
        ])
    result = json.loads(out.getvalue())
    return result.get("error_type"), code


def _check_policy(root: Path, manifest: dict, vec: dict) -> tuple[str | None, int]:
    from sage.errors import SageError
    from sage.policy import load_policy

    try:
        load_policy(root / vec["artifact"])
    except SageError as exc:
        return type(exc).__name__, 1
    return None, 0


CHECKS = {"bundle": _check_artifact, "journal": _check_artifact, "pack": _check_artifact,
          "kit": _check_kit, "policy": _check_policy}


def run(root: Path = HERE) -> list[str]:
    for name in ("SAGE_PACK_KEY", "SAGE_VERIFY_KEY", "SAGE_WITNESS_KEY", "SAGE_SIGN_PUBLIC_KEY",
                 "SAGE_SIGN_PRIVATE_KEY", "SAGE_HANDOFF_KEY", "SAGE_VERIFY_POLICY", "SAGE_REQUIRE_PACK_SIGNATURE"):
        os.environ.pop(name, None)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    failures: list[str] = []
    for vec in manifest["vectors"]:
        error_type, code = CHECKS[vec["kind"]](root, manifest, vec)
        want = vec["error_type"] if vec["expect"] == "reject" else None
        if error_type != want or code != vec["exit"]:
            failures.append(f"{vec['id']} (FORMAT.md {vec['rule']}): expected {want or 'accept'} exit {vec['exit']}, "
                            f"got {error_type or 'accept'} exit {code}")
    return failures


def main() -> int:
    sys.path.insert(0, str(HERE.parents[1] / "src"))
    manifest = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))
    failures = run(HERE)
    for line in failures:
        print("FAIL", line)
    print(f"{len(manifest['vectors']) - len(failures)}/{len(manifest['vectors'])} vectors match")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
