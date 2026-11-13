#!/usr/bin/env python3
"""Recipient check: install the built wheel in a clean environment and verify a kit offline.

    python -m build
    python scripts/recipient_check.py --dist dist [--kit path/to/handoff] [--work DIR]

1. Builds a demo kit with this (producer) interpreter unless --kit is given.
2. Creates a fresh virtual environment outside the checkout and installs the wheel from a local
   wheelhouse with --no-index (cryptography is fetched into the wheelhouse first when the kit is signed:
   that download is the documented initial-installation step).
3. Confirms `sage` imports from the new environment, not the checkout, and that LangChain is absent.
4. Runs the kit's verify_handoff.py with every socket connection blocked, plus a wrong-key negative check.

Exit 0 when every check passes. Writes recipient_report.json into the work directory.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

OFFLINE_GUARD = r'''
import runpy, socket, sys

def _blocked(*_a, **_k):
    raise OSError("network disabled by recipient_check")

socket.socket.connect = _blocked
socket.socket.connect_ex = _blocked
socket.create_connection = _blocked
socket.getaddrinfo = _blocked
script = sys.argv[1]
sys.argv = sys.argv[1:]
runpy.run_path(script, run_name="__main__")
'''


def _venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _clean_env(**extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in {"PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"} and not k.startswith("SAGE_")}
    env.update(extra)
    return env


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=900, **kw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dist", default=str(ROOT / "dist"))
    parser.add_argument("--kit", default=None, help="existing handoff dir; keys read from ../keys")
    parser.add_argument("--work", default=None, help="work dir outside the checkout (default: new temp dir)")
    args = parser.parse_args(argv)

    wheels = sorted(Path(args.dist).glob("sage_incident_bundles-*.whl"))
    if not wheels:
        print(json.dumps({"ok": False, "error": f"no wheel in {args.dist}; run python -m build"}), file=sys.stderr)
        return 2
    wheel = wheels[-1].resolve()
    work = Path(args.work).resolve() if args.work else Path(tempfile.mkdtemp(prefix="sage-recipient-"))
    if ROOT in work.parents or work == ROOT:
        print(json.dumps({"ok": False, "error": "work dir must be outside the checkout"}), file=sys.stderr)
        return 2
    work.mkdir(parents=True, exist_ok=True)
    checks: dict[str, object] = {"wheel": wheel.name, "work": str(work)}

    if args.kit:
        kit = Path(args.kit).resolve()
    else:
        run_dir = work / "producer-run"
        if run_dir.exists():
            shutil.rmtree(run_dir)
        proc = _run([sys.executable, str(ROOT / "examples" / "consultancy_demo.py"),
                     "--scenario", "tool-error", "--mode", "sync", "--out", str(run_dir)],
                    env=_clean_env(LANGCHAIN_TRACING_V2="false", LANGSMITH_TRACING="false"))
        if proc.returncode != 0:
            print(proc.stderr, file=sys.stderr)
            return 2
        kit = run_dir / "handoff"
    keys = kit.parent / "keys"
    recipient_kit = work / "recipient" / "kit"
    if recipient_kit.exists():
        shutil.rmtree(recipient_kit)
    shutil.copytree(kit, recipient_kit)
    signed = (keys / "ed25519.public.txt").exists()

    wheelhouse = work / "wheelhouse"
    wheelhouse.mkdir(exist_ok=True)
    shutil.copy2(wheel, wheelhouse / wheel.name)
    requirements = [str(wheelhouse / wheel.name)]
    if signed:
        dl = _run([sys.executable, "-m", "pip", "download", "--only-binary=:all:", "-d", str(wheelhouse), "cryptography>=42"])
        if dl.returncode != 0:
            print(dl.stderr, file=sys.stderr)
            return 2
        requirements = [f"{wheelhouse / wheel.name}[sign]"]

    venv = work / "recipient-venv"
    if venv.exists():
        shutil.rmtree(venv)
    made = _run([sys.executable, "-m", "venv", str(venv)])
    if made.returncode != 0:
        print(made.stderr, file=sys.stderr)
        return 2
    py = _venv_python(venv)
    install = _run([str(py), "-m", "pip", "install", "--no-index", "--find-links", str(wheelhouse), *requirements],
                   env=_clean_env(), cwd=work)
    checks["offline_install"] = install.returncode == 0
    if install.returncode != 0:
        print(install.stdout + install.stderr, file=sys.stderr)
        return 1

    probe = _run([str(py), "-c", "import json, importlib.util, sage; print(json.dumps({'file': sage.__file__, "
                  "'version': sage.__version__, 'langchain': importlib.util.find_spec('langchain_core') is not None}))"],
                 env=_clean_env(), cwd=work)
    info = json.loads(probe.stdout)
    sage_file = Path(info["file"]).resolve()
    checks["import_path"] = str(sage_file)
    checks["installed_version"] = info["version"]
    checks["imports_from_recipient_env"] = venv in sage_file.parents and ROOT not in sage_file.parents
    checks["langchain_absent"] = not info["langchain"]

    guard = work / "offline_guard.py"
    guard.write_text(OFFLINE_GUARD, encoding="utf-8")
    hmac_key = (keys / "hmac.key").read_text(encoding="utf-8").strip()
    verify_cmd = [str(py), str(guard), str(recipient_kit / "verify_handoff.py")]
    if signed:
        verify_cmd.append("--public-key=" + (keys / "ed25519.public.txt").read_text(encoding="utf-8").strip())
    offline_env = dict(HTTP_PROXY="http://127.0.0.1:9", HTTPS_PROXY="http://127.0.0.1:9", NO_PROXY="", PIP_NO_INDEX="1")
    ok = _run(verify_cmd, env=_clean_env(SAGE_PACK_KEY=hmac_key, **offline_env), cwd=work)
    checks["offline_verify_exit"] = ok.returncode
    checks["offline_verify"] = json.loads(ok.stdout) if ok.returncode == 0 else ok.stderr.strip()[:500]
    bad = _run(verify_cmd, env=_clean_env(SAGE_PACK_KEY="wrong-key", **offline_env), cwd=work)
    checks["wrong_key_exit"] = bad.returncode

    passed = (
        checks["offline_install"] is True
        and checks["imports_from_recipient_env"] is True
        and checks["langchain_absent"] is True
        and checks["offline_verify_exit"] == 0
        and checks["wrong_key_exit"] == 1
    )
    checks["ok"] = passed
    (work / "recipient_report.json").write_text(json.dumps(checks, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(checks, indent=2, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
