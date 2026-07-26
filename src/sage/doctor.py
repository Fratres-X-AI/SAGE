"""Environment / integrity self-check for operators (`sage doctor`)."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from sage.version import __version__, version_report


def run_doctor(*, deep: bool = True) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    ok = True

    def add(name: str, passed: bool, detail: str = "", *, advisory: bool = False) -> None:
        nonlocal ok
        checks.append({"name": name, "ok": passed, "detail": detail, **({"advisory": True} if advisory else {})})
        if not passed and not advisory:
            ok = False

    add("python>=3.10", sys.version_info >= (3, 10), sys.version.split()[0])
    add("sage_version", bool(__version__), __version__)
    try:
        from sage import SageRecorder, verify_artifact  # noqa: F401

        add("import_core", True, "sage imports ok")
    except Exception as exc:
        add("import_core", False, str(exc))

    from sage.signing import signing_available

    add(
        "optional_ed25519",
        True,
        "available" if signing_available() else "not installed (pip install -e '.[sign]')",
        advisory=True,
    )

    for env_name in ("SAGE_PACK_KEY", "SAGE_WITNESS_KEY", "SAGE_VERIFY_KEY", "SAGE_HEAL_KEY"):
        present = bool(os.environ.get(env_name))
        add(f"env_{env_name}", True, "set" if present else "unset", advisory=True)

    req_sig = bool(os.environ.get("SAGE_REQUIRE_PACK_SIGNATURE"))
    pinned = bool(os.environ.get("SAGE_SIGN_PUBLIC_KEY"))
    if req_sig:
        add(
            "pinned_public_key_for_require_signature",
            pinned,
            "SAGE_SIGN_PUBLIC_KEY set" if pinned else "SAGE_REQUIRE_PACK_SIGNATURE set but no SAGE_SIGN_PUBLIC_KEY",
        )
    else:
        add(
            "env_SAGE_SIGN_PUBLIC_KEY",
            True,
            "set" if pinned else "unset",
            advisory=True,
        )

    if deep and ok:
        try:
            with tempfile.TemporaryDirectory(prefix="sage-doctor-") as tmp:
                root = Path(tmp)
                from sage.recorder import SageRecorder
                from sage.pack import pack_artifact
                from sage.verify import verify_artifact
                from sage.handoff import create_handoff
                from sage.signing import generate_keypair, signing_available

                key = os.environ.get("SAGE_PACK_KEY") or "doctor-ephemeral-key"
                with SageRecorder("doctor", blob_store=root / "b", register_trace=False) as rec:
                    with rec.tool_call("t", inputs={"api_key": "sk-doctorcheck1", "q": "x"}):
                        pass
                    path = rec.export(root / "inc.sage.json")
                pack = pack_artifact(path, root / "p.sage.tar.gz", hmac_key=key)
                report = verify_artifact(
                    pack,
                    hmac_key=key,
                    check_witness=True,
                    witness_key=key,
                )
                add("mini_verify_loop", bool(report.get("ok")), report.get("bundle_hash", "")[:16])
                kit = create_handoff(path, root / "kit", hmac_key=key)
                add("handoff_kit", (kit / "evidence.sage.tar.gz").exists(), str(kit))

                if signing_available():
                    kp = generate_keypair()
                    prev_priv = os.environ.get("SAGE_SIGN_PRIVATE_KEY")
                    prev_pub = os.environ.get("SAGE_SIGN_PUBLIC_KEY")
                    os.environ["SAGE_SIGN_PRIVATE_KEY"] = kp["private_key"]
                    os.environ["SAGE_SIGN_PUBLIC_KEY"] = kp["public_key"]
                    try:
                        signed = pack_artifact(
                            path, root / "signed.sage.tar.gz", hmac_key=key, sign=True
                        )
                        srep = verify_artifact(
                            signed,
                            hmac_key=key,
                            require_signature=True,
                            public_key=kp["public_key"],
                        )
                        add("ed25519_pinned_verify", bool(srep.get("ok")), "pinned path ok")
                    finally:
                        if prev_priv is None:
                            os.environ.pop("SAGE_SIGN_PRIVATE_KEY", None)
                        else:
                            os.environ["SAGE_SIGN_PRIVATE_KEY"] = prev_priv
                        if prev_pub is None:
                            os.environ.pop("SAGE_SIGN_PUBLIC_KEY", None)
                        else:
                            os.environ["SAGE_SIGN_PUBLIC_KEY"] = prev_pub
        except Exception as exc:
            add("mini_verify_loop", False, str(exc))

    return {
        "ok": ok,
        "sage_version": __version__,
        "formats": version_report()["formats"],
        "checks": checks,
    }
