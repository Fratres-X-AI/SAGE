#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

HOST="${RUNPOD_HOST:-root@157.157.221.29}"
PORT="${RUNPOD_PORT:-33922}"
KEY="${RUNPOD_SSH_KEY:-$HOME/.ssh/id_ed25519}"
MINUTES="${SOAK_MINUTES:-45}"

echo "Stopping prior soak processes on pod..."
ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -i "$KEY" -p "$PORT" "$HOST" \
  'pkill -f "scripts/pod_soak_max.sh" 2>/dev/null || true; pkill -f "test_nuclear_stress" 2>/dev/null || true; pkill -f "/workspace/SAGE/.venv/bin/pytest" 2>/dev/null || true; sleep 2; echo cleared' \
  || echo "(stop ssh returned non-zero — continuing)"

echo "Syncing forensics tree -> ${HOST}:${PORT}"
tar czf - \
  --exclude='.venv' \
  --exclude='.pytest_cache' \
  --exclude='.git' \
  --exclude='artifacts' \
  --exclude='pod_export' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --exclude='*.cmd' \
  --exclude='sage_soak_logs' \
  --exclude='sage_soak_tmp' \
  . | ssh -o BatchMode=yes -i "$KEY" -p "$PORT" "$HOST" \
  'mkdir -p /workspace/SAGE && find /workspace/SAGE -mindepth 1 -maxdepth 1 ! -name .venv ! -name sage_soak_logs ! -name sage_soak_tmp -exec rm -rf {} + && tar xzf - -C /workspace/SAGE --no-same-owner --no-same-permissions'

echo "Launching ${MINUTES}m max soak (isolated basetemps, cgroup workers)..."
ssh -o BatchMode=yes -T -i "$KEY" -p "$PORT" "$HOST" \
  "sed -i 's/\r$//' /workspace/SAGE/scripts/*.sh && SOAK_MINUTES=${MINUTES} bash /workspace/SAGE/scripts/pod_soak_max.sh"
