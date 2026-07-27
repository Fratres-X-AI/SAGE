#!/usr/bin/env python3
"""Generate a minimal SPDX-lite SBOM for the SAGE source tree (stdlib only)."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "sage"


def file_entry(path: Path) -> dict:
    data = path.read_bytes()
    rel = path.relative_to(ROOT).as_posix()
    return {
        "SPDXID": f"SPDXRef-File-{hashlib.sha256(rel.encode()).hexdigest()[:16]}",
        "fileName": rel,
        "checksums": [{"algorithm": "SHA256", "checksumValue": hashlib.sha256(data).hexdigest()}],
    }


def main() -> int:
    files = sorted(p for p in SRC.rglob("*.py") if p.is_file())
    version = "unknown"
    try:
        from sage.version import __version__

        version = __version__
    except Exception:
        pass
    namespace = os.environ.get(
        "SAGE_SBOM_NAMESPACE",
        f"https://github.com/Fratres-X-AI/SAGE/{version}",
    )
    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"sage-incident-bundles-{version}",
        "documentNamespace": namespace,
        "creationInfo": {
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": ["Tool: scripts/generate_sbom.py"],
        },
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-sage",
                "name": "sage-incident-bundles",
                "versionInfo": version,
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": "FSL-1.1-ALv2",
                "licenseDeclared": "FSL-1.1-ALv2",
            }
        ],
        "files": [file_entry(p) for p in files],
    }
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "dist" / "sbom.spdx.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
