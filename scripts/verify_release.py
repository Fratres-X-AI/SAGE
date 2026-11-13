#!/usr/bin/env python3
"""Verify a downloaded SAGE release directory before installing it.

Checks, in order (each one fails closed):

1. checksums   every file listed in SHA256SUMS.json exists and matches its SHA-256.
2. sigstore    each wheel/sdist/SBOM has a <file>.sigstore.json bundle whose certificate was issued
               to this repository's release workflow for the given tag (needs `pip install sigstore`).
3. provenance  each wheel/sdist/verifier has a GitHub SLSA build-provenance attestation from this repository
               (needs the GitHub CLI `gh`).

Exit codes: 0 all requested checks passed; 1 a check failed; 2 setup problem (missing file or tool).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

DEFAULT_REPO = "Fratres-X-AI/SAGE"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
SIGNED_SUFFIXES = (".whl", ".tar.gz", ".pyz", ".spdx.json")


class SetupError(Exception):
    pass


def check_checksums(dist: Path) -> list[str]:
    sums_path = dist / "SHA256SUMS.json"
    if not sums_path.is_file():
        raise SetupError("SHA256SUMS.json not found")
    sums = json.loads(sums_path.read_text(encoding="utf-8"))
    problems = []
    for name, expected in sorted(sums.items()):
        path = dist / name
        if not path.is_file():
            problems.append(f"{name}: listed in SHA256SUMS.json but missing")
        elif hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            problems.append(f"{name}: SHA-256 mismatch")
    if not any(n.endswith(".whl") for n in sums):
        problems.append("SHA256SUMS.json lists no wheel")
    return problems


def signed_subjects(dist: Path) -> list[Path]:
    return sorted(p for p in dist.iterdir() if p.is_file() and p.name.endswith(SIGNED_SUFFIXES))


def sigstore_command(artifact: Path, *, repo: str, tag: str) -> list[str]:
    identity = f"https://github.com/{repo}/.github/workflows/release.yml@refs/tags/{tag}"
    return [sys.executable, "-m", "sigstore", "verify", "identity", str(artifact),
            "--bundle", f"{artifact}.sigstore.json",
            "--cert-identity", identity, "--cert-oidc-issuer", OIDC_ISSUER]


def provenance_command(artifact: Path, *, repo: str) -> list[str]:
    return ["gh", "attestation", "verify", str(artifact), "--repo", repo,
            "--signer-workflow", f"{repo}/.github/workflows/release.yml"]


def _run(cmd: list[str]) -> tuple[bool, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    detail = (proc.stderr or proc.stdout).strip().splitlines()
    return proc.returncode == 0, detail[-1][:300] if detail else ""


def check_sigstore(dist: Path, *, repo: str, tag: str) -> list[str]:
    probe = subprocess.run([sys.executable, "-m", "sigstore", "--version"], capture_output=True, text=True)
    if probe.returncode != 0:
        raise SetupError("sigstore is not installed: python -m pip install sigstore")
    problems = []
    for artifact in signed_subjects(dist):
        if not Path(f"{artifact}.sigstore.json").is_file():
            problems.append(f"{artifact.name}: no .sigstore.json bundle")
            continue
        ok, detail = _run(sigstore_command(artifact, repo=repo, tag=tag))
        if not ok:
            problems.append(f"{artifact.name}: sigstore verification failed: {detail}")
    return problems


def check_provenance(dist: Path, *, repo: str) -> list[str]:
    if shutil.which("gh") is None:
        raise SetupError("GitHub CLI (gh) is not installed: https://cli.github.com/")
    problems = []
    for artifact in signed_subjects(dist):
        if artifact.name.endswith(".spdx.json"):
            continue
        ok, detail = _run(provenance_command(artifact, repo=repo))
        if not ok:
            problems.append(f"{artifact.name}: provenance verification failed: {detail}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("dist", help="directory holding the downloaded release files")
    parser.add_argument("--tag", required=True, help="release tag, for example v2.3.0")
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--skip", action="append", default=[], choices=["sigstore", "provenance"],
                        help="skip a check (reported as skipped, never as passed)")
    args = parser.parse_args(argv)
    dist = Path(args.dist)
    if not dist.is_dir():
        print(json.dumps({"ok": False, "stage": "setup", "error": f"not a directory: {dist}"}))
        return 2
    report: dict[str, object] = {"tag": args.tag, "repo": args.repo, "checks": {}}
    checks = report["checks"]
    assert isinstance(checks, dict)
    runners = [
        ("checksums", lambda: check_checksums(dist)),
        ("sigstore", lambda: check_sigstore(dist, repo=args.repo, tag=args.tag)),
        ("provenance", lambda: check_provenance(dist, repo=args.repo)),
    ]
    code = 0
    for name, run in runners:
        if name in args.skip:
            checks[name] = "skipped"
            continue
        try:
            problems = run()
        except SetupError as exc:
            checks[name] = {"ok": False, "setup_error": str(exc)}
            code = max(code, 2)
            continue
        checks[name] = {"ok": not problems, "problems": problems}
        if problems:
            code = 1 if code != 2 else 2
    report["ok"] = code == 0
    print(json.dumps(report, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
