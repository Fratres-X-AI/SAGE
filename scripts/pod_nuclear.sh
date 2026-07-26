#!/usr/bin/env bash
# Run SAGE nuclear / full suite on a RunPod (or any cgroup-limited host).
# Uses cgroup CPU quota for workers — never nproc.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CGROUP_CPUS="$(bash scripts/cgroup_cpus.sh)"
echo "cgroup_cpus=${CGROUP_CPUS} (nproc=$(nproc) — ignored)"

if [[ "${CGROUP_CPUS}" == "unlimited" || "${CGROUP_CPUS}" == "unknown" ]]; then
  WORKERS="${SAGE_NUCLEAR_WORKERS:-32}"
else
  # Leave 2 cores for OS / pytest parent.
  WORKERS="${SAGE_NUCLEAR_WORKERS:-$(( CGROUP_CPUS > 4 ? CGROUP_CPUS - 2 : CGROUP_CPUS ))}"
fi
export SAGE_NUCLEAR_WORKERS="${WORKERS}"
echo "SAGE_NUCLEAR_WORKERS=${SAGE_NUCLEAR_WORKERS}"

python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install -q -U pip
python -m pip install -q -e ".[dev]"

echo "=== sage doctor ==="
sage doctor --quick

# Research attribution needs numpy/torch — not part of forensics custody path.
IGNORE=(--ignore=tests/test_attribution.py)

echo "=== forensics pytest (nuclear uses SAGE_NUCLEAR_WORKERS) ==="
pytest -q --tb=line "${IGNORE[@]}"
echo "=== nuclear verbose ==="
pytest tests/test_nuclear_stress.py -v -s --tb=short
echo "DONE workers=${SAGE_NUCLEAR_WORKERS}"
