#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PY="${ROOT}/.venv/Scripts/python.exe"
if [[ ! -x "$PY" ]]; then
  PY=python3
fi
export SAGE_PACK_KEY="${SAGE_PACK_KEY:-ci-key}"
"$PY" scripts/release_check.py
"$PY" -m pytest tests -q --tb=line
"$PY" examples/security_verify_loop.py
"$PY" examples/auditor_kit.py
"$PY" scripts/ci_smoke.py
"$PY" -c "from sage.doctor import run_doctor; r=run_doctor(deep=True); print(r['ok'], r['sage_version']); raise SystemExit(0 if r['ok'] else 1)"
echo "ALL LOCAL GATES GREEN"
