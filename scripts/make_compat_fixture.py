"""Generate sealed compatibility fixtures with whatever SAGE version is importable.

Usage: python scripts/make_compat_fixture.py <out_dir>
Writes bundle.sage.json, evidence.sage.tar.gz (HMAC key below), blobs/, and fixture.json.
The HMAC key is a published test constant, not a secret.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

FIXTURE_HMAC_KEY = "sage-compat-fixture-key-not-secret"


def main() -> int:
    import sage
    from sage import SageRecorder
    from sage.pack import pack_artifact

    import os

    target = Path(sys.argv[1]).resolve()
    target.mkdir(parents=True, exist_ok=True)
    os.chdir(target)
    out = Path(".")
    blobs = Path("blobs")
    rec = SageRecorder(title="compat fixture", trace_id="compat-fixture", blob_store=blobs, journal_dir=Path("journal"))
    with rec:
        with rec.chain("support-flow", inputs={"question": "Where is order 42?"}) as chain:
            with rec.llm_call("model", inputs={"prompt": "Where is order 42?"}, data={"model": "deterministic-test-model"}) as llm:
                llm.set_output(text="Order 42 shipped.")
            with rec.tool_call("history", inputs={"q": "orders"}) as tool:
                tool.set_output(documents=["line " * 400])
            chain.set_output(answer="Order 42 shipped.")
    bundle_path = rec.export(out / "bundle.sage.json")
    pack = pack_artifact(out / "journal", out / "evidence.sage.tar.gz", blob_store=blobs, hmac_key=FIXTURE_HMAC_KEY)
    (out / "fixture.json").write_text(
        json.dumps(
            {
                "sage_version": getattr(sage, "__version__", "unknown"),
                "bundle": bundle_path.name,
                "pack": Path(pack).name,
                "hmac_key": FIXTURE_HMAC_KEY,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
