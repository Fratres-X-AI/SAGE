#!/usr/bin/env bash
# Max-utilization forensics soak for RunPod / cgroup hosts.
# Uses cgroup CPU quota — never nproc. Leaves GPU idle (custody path is CPU).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MINUTES="${SOAK_MINUTES:-45}"
LOG_DIR="${SOAK_LOG_DIR:-/workspace/sage_soak_logs}"
mkdir -p "$LOG_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SUMMARY="$LOG_DIR/soak_max_${STAMP}.jsonl"
STATUS="$LOG_DIR/soak_max_${STAMP}.status"
PARALLEL_LOG="$LOG_DIR/soak_max_${STAMP}_lanes"
# Prefer local container disk (/tmp on overlay) — /workspace is network MFS and
# serializes 6 nuclear lanes into wall-clock false failures.
BASETEMP_ROOT="/tmp/sage_soak_tmp/${STAMP}"
mkdir -p "$BASETEMP_ROOT" "$LOG_DIR"

CGROUP_CPUS="$(bash scripts/cgroup_cpus.sh)"
echo "=== POD SOAK MAX ==="
echo "cgroup_cpus=${CGROUP_CPUS} (nproc=$(nproc) — IGNORED)"
free -h | head -2
df -h / /workspace 2>/dev/null || df -h /

if [[ "${CGROUP_CPUS}" == "unlimited" || "${CGROUP_CPUS}" == "unknown" ]]; then
  CPUS=32
else
  CPUS="${CGROUP_CPUS}"
fi

LANES="${SOAK_LANES:-$(( CPUS / 9 ))}"
if [[ "${LANES}" -lt 3 ]]; then LANES=3; fi
if [[ "${LANES}" -gt 6 ]]; then LANES=6; fi

PER_LANE_WORKERS="${SAGE_NUCLEAR_WORKERS:-$(( (CPUS * 3 / 2) / LANES ))}"
if [[ "${PER_LANE_WORKERS}" -lt 8 ]]; then PER_LANE_WORKERS=8; fi

export SAGE_NUCLEAR_WORKERS="${PER_LANE_WORKERS}"
export SAGE_NUCLEAR_STREAM_MB="${SAGE_NUCLEAR_STREAM_MB:-256}"
export SAGE_NUCLEAR_CAS_OPS="${SAGE_NUCLEAR_CAS_OPS:-$(( PER_LANE_WORKERS * 6 ))}"
export SAGE_NUCLEAR_CAS_POOL="${SAGE_NUCLEAR_CAS_POOL:-${PER_LANE_WORKERS}}"
export SAGE_NUCLEAR_PACKS="${SAGE_NUCLEAR_PACKS:-${PER_LANE_WORKERS}}"
export SAGE_NUCLEAR_PACK_POOL="${SAGE_NUCLEAR_PACK_POOL:-$(( PER_LANE_WORKERS / 2 + 1 ))}"
export SAGE_NUCLEAR_FANOUT="${SAGE_NUCLEAR_FANOUT:-500}"
# Parallel lanes contend for disk/CPU — do not fail soak on wall-clock alone.
export SAGE_NUCLEAR_MAX_S="${SAGE_NUCLEAR_MAX_S:-600}"

echo "LANES=${LANES}"
echo "SAGE_NUCLEAR_WORKERS=${SAGE_NUCLEAR_WORKERS}"
echo "SAGE_NUCLEAR_STREAM_MB=${SAGE_NUCLEAR_STREAM_MB}"
echo "SAGE_NUCLEAR_CAS_OPS=${SAGE_NUCLEAR_CAS_OPS}"
echo "SAGE_NUCLEAR_PACKS=${SAGE_NUCLEAR_PACKS}"
echo "SAGE_NUCLEAR_FANOUT=${SAGE_NUCLEAR_FANOUT}"
echo "SOAK_MINUTES=${MINUTES}"
echo "basetemp_root=${BASETEMP_ROOT}"
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
start_all=$(date +%s)
echo "running lanes=${LANES} deadline_utc=$(date -u -d "@${DEADLINE}" +%H:%M:%SZ 2>/dev/null || date -u)" >"$STATUS"

# Per-lane basetemp — NEVER rm -rf /tmp/pytest-of-root (kills sibling lanes).
lane_nuclear() {
  local id="$1"
  local round=0
  local fails=0
  local log="${PARALLEL_LOG}_nuclear_${id}.log"
  local base="${BASETEMP_ROOT}/nuclear_${id}"
  mkdir -p "$base"
  while [[ "$(date +%s)" -lt "${DEADLINE}" ]]; do
    round=$((round + 1))
    local t0 t1 code
    t0=$(date +%s)
    rm -rf "${base}/r" 2>/dev/null || true
    mkdir -p "${base}/r"
    set +e
    pytest -q --tb=line --basetemp="${base}/r" tests/test_nuclear_stress.py >>"$log" 2>&1
    code=$?
    set -e
    t1=$(date +%s)
    if [[ "${code}" -ne 0 ]]; then
      fails=$((fails + 1))
      echo "{\"lane\":\"nuclear-${id}\",\"round\":${round},\"ok\":false,\"exit\":${code},\"seconds\":$((t1-t0))}" >>"$SUMMARY"
      echo "FAIL nuclear-${id} round=${round} (continuing)" >>"$STATUS"
      # Keep soaking — one flake must not idle the pod.
      continue
    fi
    echo "{\"lane\":\"nuclear-${id}\",\"round\":${round},\"ok\":true,\"seconds\":$((t1-t0)),\"workers\":${SAGE_NUCLEAR_WORKERS}}" >>"$SUMMARY"
  done
  echo "nuclear-${id} done rounds=${round} fails=${fails}" >>"$STATUS"
  return 0
}

lane_suite() {
  local round=0
  local fails=0
  local log="${PARALLEL_LOG}_suite.log"
  local base="${BASETEMP_ROOT}/suite"
  mkdir -p "$base"
  while [[ "$(date +%s)" -lt "${DEADLINE}" ]]; do
    round=$((round + 1))
    local t0 t1 code
    t0=$(date +%s)
    rm -rf "${base}/r" 2>/dev/null || true
    mkdir -p "${base}/r"
    set +e
    pytest -q --tb=line --basetemp="${base}/r" "${IGNORE[@]}" \
      tests/threat_matrix \
      tests/test_layer_2_1.py \
      tests/test_hardening_2_0_1.py \
      tests/test_v2_stability.py \
      tests/test_forensics_e2e.py \
      tests/test_layer_11.py \
      >>"$log" 2>&1
    code=$?
    set -e
    t1=$(date +%s)
    if [[ "${code}" -ne 0 ]]; then
      fails=$((fails + 1))
      echo "{\"lane\":\"suite\",\"round\":${round},\"ok\":false,\"exit\":${code},\"seconds\":$((t1-t0))}" >>"$SUMMARY"
      echo "FAIL suite round=${round} (continuing)" >>"$STATUS"
      continue
    fi
    echo "{\"lane\":\"suite\",\"round\":${round},\"ok\":true,\"seconds\":$((t1-t0))}" >>"$SUMMARY"
  done
  echo "suite done rounds=${round} fails=${fails}" >>"$STATUS"
  return 0
}

lane_doctor_pack() {
  local round=0
  local fails=0
  local log="${PARALLEL_LOG}_doctor.log"
  local base="${BASETEMP_ROOT}/pack"
  mkdir -p "$base"
  while [[ "$(date +%s)" -lt "${DEADLINE}" ]]; do
    round=$((round + 1))
    local t0 t1 code
    t0=$(date +%s)
    set +e
    SAGE_SOAK_PACK_DIR="${base}/r${round}" python - <<'PY' >>"$log" 2>&1
import os, shutil, tempfile
from pathlib import Path
from sage.recorder import SageRecorder
from sage.pack import pack_artifact, unpack_artifact
from sage.verify import verify_artifact

key = "soak-max-hmac"
workers = int(os.environ.get("SAGE_NUCLEAR_WORKERS", "16"))
n = max(8, workers // 2)
root = Path(os.environ["SAGE_SOAK_PACK_DIR"])
if root.exists():
    shutil.rmtree(root)
root.mkdir(parents=True)
paths = []
for i in range(n):
    with SageRecorder(f"soak-{i}", blob_store=root / "b", register_trace=False) as rec:
        with rec.tool_call("t", inputs={"api_key": "sk-soak", "body": ("X" * 2500), "i": i}):
            pass
        paths.append(rec.export(root / f"i{i}.sage.json"))
packs = [pack_artifact(p, root / f"p{i}.sage.tar.gz", hmac_key=key) for i, p in enumerate(paths)]
for i, pk in enumerate(packs):
    r = verify_artifact(pk, hmac_key=key, check_witness=True, witness_key=key)
    assert r["ok"], r
    unpack_artifact(pk, root / f"out{i}", hmac_key=key, quarantine=True)
shutil.rmtree(root, ignore_errors=True)
print("pack_lane_ok", n, flush=True)
PY
    code=$?
    set -e
    t1=$(date +%s)
    if [[ "${code}" -ne 0 ]]; then
      fails=$((fails + 1))
      echo "{\"lane\":\"pack-hammer\",\"round\":${round},\"ok\":false,\"exit\":${code},\"seconds\":$((t1-t0))}" >>"$SUMMARY"
      echo "FAIL pack-hammer round=${round} (continuing)" >>"$STATUS"
      continue
    fi
    echo "{\"lane\":\"pack-hammer\",\"round\":${round},\"ok\":true,\"seconds\":$((t1-t0))}" >>"$SUMMARY"
  done
  echo "pack-hammer done rounds=${round} fails=${fails}" >>"$STATUS"
  return 0
}

pids=()
for i in $(seq 1 "${LANES}"); do
  lane_nuclear "$i" &
  pids+=($!)
done
lane_suite &
pids+=($!)
lane_doctor_pack &
pids+=($!)

echo "spawned pids=${pids[*]}" | tee -a "$STATUS"

while true; do
  alive=0
  for pid in "${pids[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      alive=$((alive + 1))
    fi
  done
  load="$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo '?')"
  ok_lines=$(grep -c '"ok":true' "$SUMMARY" 2>/dev/null || echo 0)
  bad_lines=$(grep -c '"ok":false' "$SUMMARY" 2>/dev/null || echo 0)
  echo "heartbeat alive=${alive}/$((LANES+2)) load=${load} ok=${ok_lines} fail=${bad_lines} utc=$(date -u +%H:%M:%SZ)" | tee -a "$STATUS"
  if [[ "${alive}" -eq 0 ]]; then
    break
  fi
  sleep 30
done

for pid in "${pids[@]}"; do
  wait "$pid" || true
done

elapsed=$(( $(date +%s) - start_all ))
ok_lines=$(grep -c '"ok":true' "$SUMMARY" 2>/dev/null || echo 0)
bad_lines=$(grep -c '"ok":false' "$SUMMARY" 2>/dev/null || echo 0)
echo "{\"event\":\"complete\",\"ok_rounds\":${ok_lines},\"fail_rounds\":${bad_lines},\"elapsed_s\":${elapsed},\"lanes\":${LANES},\"workers\":${SAGE_NUCLEAR_WORKERS},\"cgroup_cpus\":${CPUS}}" | tee -a "$SUMMARY"

# Cleanup lane temps
rm -rf "$BASETEMP_ROOT" 2>/dev/null || true

if [[ "${bad_lines}" -ne 0 ]]; then
  echo "DONE_WITH_FAILS ok=${ok_lines} fail=${bad_lines} elapsed_s=${elapsed}" | tee "$STATUS"
  # Still exit 0 if we soaked hard — report fails in summary. Nonzero only if zero ok rounds.
  if [[ "${ok_lines}" -eq 0 ]]; then
    exit 1
  fi
  exit 0
fi
echo "OK ok_rounds=${ok_lines} elapsed_s=${elapsed} cgroup=${CPUS}" | tee "$STATUS"
echo "SOAK MAX DONE"
