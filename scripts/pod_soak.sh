#!/usr/bin/env bash
# Sustained forensics soak on cgroup-limited hosts (RunPod). Never uses nproc.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MINUTES="${SOAK_MINUTES:-15}"
ROUNDS="${SOAK_ROUNDS:-0}"   # 0 = time-bounded; >0 = fixed round count
LOG_DIR="${SOAK_LOG_DIR:-/workspace/sage_soak_logs}"
mkdir -p "$LOG_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SUMMARY="$LOG_DIR/soak_${STAMP}.jsonl"
STATUS="$LOG_DIR/soak_${STAMP}.status"

CGROUP_CPUS="$(bash scripts/cgroup_cpus.sh)"
echo "cgroup_cpus=${CGROUP_CPUS} (nproc=$(nproc) — ignored)"
if [[ "${CGROUP_CPUS}" == "unlimited" || "${CGROUP_CPUS}" == "unknown" ]]; then
  WORKERS="${SAGE_NUCLEAR_WORKERS:-32}"
else
  WORKERS="${SAGE_NUCLEAR_WORKERS:-$(( CGROUP_CPUS > 4 ? CGROUP_CPUS - 2 : CGROUP_CPUS ))}"
fi
export SAGE_NUCLEAR_WORKERS="${WORKERS}"
echo "SAGE_NUCLEAR_WORKERS=${SAGE_NUCLEAR_WORKERS}"
echo "SOAK_MINUTES=${MINUTES} SOAK_ROUNDS=${ROUNDS}"
echo "log=${SUMMARY}"

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install -q -U pip
python -m pip install -q -e ".[dev]"

IGNORE=(--ignore=tests/test_attribution.py)
DEADLINE=$(( $(date +%s) + MINUTES * 60 ))
round=0
failures=0
start_all=$(date +%s)

echo "running" >"$STATUS"
trap 'echo "interrupted round=${round}" >"$STATUS"' INT TERM

while true; do
  round=$((round + 1))
  if [[ "${ROUNDS}" -gt 0 && "${round}" -gt "${ROUNDS}" ]]; then
    break
  fi
  if [[ "${ROUNDS}" -eq 0 && "$(date +%s)" -ge "${DEADLINE}" ]]; then
    break
  fi

  t0=$(date +%s)
  echo "=== soak round ${round} @ $(date -u +%H:%M:%SZ) ==="
  set +e
  pytest -q --tb=line "${IGNORE[@]}" \
    tests/test_nuclear_stress.py \
    tests/threat_matrix \
    tests/test_layer_2_1.py \
    tests/test_hardening_2_0_1.py \
    tests/test_v2_stability.py
  code=$?
  set -e
  t1=$(date +%s)
  dur=$((t1 - t0))

  if [[ "${code}" -eq 0 ]]; then
    echo "{\"round\":${round},\"ok\":true,\"seconds\":${dur},\"workers\":${SAGE_NUCLEAR_WORKERS},\"utc\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" | tee -a "$SUMMARY"
  else
    failures=$((failures + 1))
    echo "{\"round\":${round},\"ok\":false,\"exit\":${code},\"seconds\":${dur},\"workers\":${SAGE_NUCLEAR_WORKERS},\"utc\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" | tee -a "$SUMMARY"
    echo "FAILED" >"$STATUS"
    echo "Soak aborted on round ${round} (exit=${code})"
    exit "${code}"
  fi
done

elapsed=$(( $(date +%s) - start_all ))
echo "{\"rounds\":${round},\"failures\":${failures},\"elapsed_s\":${elapsed},\"workers\":${SAGE_NUCLEAR_WORKERS},\"cgroup_cpus\":\"${CGROUP_CPUS}\",\"utc\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" | tee -a "$SUMMARY"
echo "ok rounds=${round} elapsed_s=${elapsed}" >"$STATUS"
echo "SOAK DONE rounds=${round} failures=${failures} elapsed_s=${elapsed}"
cat "$STATUS"
