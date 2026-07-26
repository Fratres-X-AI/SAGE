#!/usr/bin/env bash
# Hot-patch soak scripts/tests and restart max soak without full tree sync.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
HOST="${RUNPOD_HOST:-root@157.157.221.29}"
PORT="${RUNPOD_PORT:-33922}"
KEY="${RUNPOD_SSH_KEY:-$HOME/.ssh/id_ed25519}"
MINUTES="${SOAK_MINUTES:-50}"

echo "Stop prior soak..."
ssh -o BatchMode=yes -i "$KEY" -p "$PORT" "$HOST" \
  'pkill -f "scripts/pod_soak_max.sh" 2>/dev/null || true; pkill -f "test_nuclear_stress" 2>/dev/null || true; pkill -f "/workspace/SAGE/.venv/bin/pytest" 2>/dev/null || true; rm -rf /tmp/sage_soak_tmp /tmp/pytest-of-root 2>/dev/null || true; echo cleared' \
  || echo "(stop non-zero — continuing)"

echo "Push patched files..."
ssh -o BatchMode=yes -i "$KEY" -p "$PORT" "$HOST" 'mkdir -p /workspace/SAGE/scripts /workspace/SAGE/tests /workspace/SAGE/patch'
scp -o BatchMode=yes -i "$KEY" -P "$PORT" \
  scripts/pod_soak_max.sh \
  scripts/cgroup_cpus.sh \
  tests/test_nuclear_stress.py \
  "$HOST:/workspace/SAGE/patch/"
ssh -o BatchMode=yes -i "$KEY" -p "$PORT" "$HOST" \
  'mv /workspace/SAGE/patch/pod_soak_max.sh /workspace/SAGE/patch/cgroup_cpus.sh /workspace/SAGE/scripts/ && mv /workspace/SAGE/patch/test_nuclear_stress.py /workspace/SAGE/tests/ && rmdir /workspace/SAGE/patch 2>/dev/null || true; sed -i "s/\r$//" /workspace/SAGE/scripts/*.sh'

echo "Launch ${MINUTES}m soak on local /tmp basetemps..."
ssh -o BatchMode=yes -T -i "$KEY" -p "$PORT" "$HOST" \
  "SOAK_MINUTES=${MINUTES} bash /workspace/SAGE/scripts/pod_soak_max.sh"
