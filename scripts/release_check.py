#!/usr/bin/env python3
"""Pre-release / OSS launch gate (stdlib + installed sage). No outside services."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    from sage.version import FORMATS, STABLE_PUBLIC_API, __version__

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M)
    if not m:
        fail("pyproject.toml missing version")
    if m.group(1) != __version__:
        fail(f"version drift pyproject={m.group(1)} sage.version={__version__}")

    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    if f"## {__version__}" not in changelog and f"## {__version__} " not in changelog:
        # Allow "## 2.1.1 — date"
        if f"## {__version__}" not in changelog:
            fail(f"CHANGELOG.md missing section for {__version__}")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    if __version__ not in readme:
        fail(f"README.md does not mention {__version__}")

    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    if __version__.split(".")[0:2] == ["2", "1"] and "2.1" not in security:
        fail("SECURITY.md should mention 2.1.x support line")

    required = [
        "THREAT_MODEL.md",
        "COMPATIBILITY.md",
        "LICENSE",
        "COMMERCIAL.md",
        "docs/VERIFY_RUNBOOK.md",
        "docs/AUDITOR_KIT.md",
        "RELEASE.md",
        "policies/strict.json",
        "policies/auditor.json",
        "examples/security_verify_loop.py",
        "examples/auditor_kit.py",
        "examples/keys.ring.example.json",
    ]
    runbook = (ROOT / "docs" / "VERIFY_RUNBOOK.md").read_text(encoding="utf-8")
    if "require-signature" not in runbook or "AUDITOR_KIT" not in runbook:
        fail("VERIFY_RUNBOOK.md missing pinned-signature / auditor kit path")
    lic = (ROOT / "LICENSE").read_text(encoding="utf-8")
    if "FSL-1.1-ALv2" not in lic or "Competing Use" not in lic:
        fail("LICENSE must be FSL-1.1-ALv2 with Competing Use terms")
    if 'license = { text = "FSL-1.1-ALv2" }' not in (ROOT / "pyproject.toml").read_text(encoding="utf-8"):
        fail("pyproject.toml must declare FSL-1.1-ALv2")
    for rel in required:
        if not (ROOT / rel).is_file():
            fail(f"missing required file {rel}")

    # Format freeze presence
    for key in ("journal", "pack", "policy", "receipt", "keys", "witness"):
        if key not in FORMATS:
            fail(f"FORMATS missing {key}")

    if "sage.verify_artifact" not in STABLE_PUBLIC_API:
        fail("STABLE_PUBLIC_API missing verify_artifact")

    # Policy schemas load
    from sage.policy import load_policy

    load_policy(ROOT / "policies" / "strict.json")
    load_policy(ROOT / "policies" / "auditor.json")

    print(
        json.dumps(
            {
                "ok": True,
                "sage_version": __version__,
                "formats": FORMATS,
                "stable_api_count": len(STABLE_PUBLIC_API),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
