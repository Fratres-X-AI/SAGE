#!/usr/bin/env bash
# Start CPU burn alongside an already-running soak (does not stop soak).
set -euo pipefail
HOST="${RUNPOD_HOST:-root@157.157.221.29}"
PORT="${RUNPOD_PORT:-33922}"
KEY="${RUNPOD_SSH_KEY:-$HOME/.ssh/id_ed25519}"
MINUTES="${SOAK_MINUTES:-45}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

scp -o BatchMode=yes -i "$KEY" -P "$PORT" "$ROOT/scripts/pod_soak_burn.py" \
  "$HOST:/workspace/SAGE/scripts/pod_soak_burn.py"
ssh -o BatchMode=yes -i "$KEY" -p "$PORT" "$HOST" \
  "sed -i 's/\r$//' /workspace/SAGE/scripts/pod_soak_burn.py && \
   nohup bash -lc 'cd /workspace/SAGE && source .venv/bin/activate && \
   SOAK_MINUTES=${MINUTES} SOAK_BURN_WORKERS=32 python scripts/pod_soak_burn.py \
   > /workspace/sage_soak_logs/burn_stdout.log 2>&1' >/dev/null 2>&1 & echo burn_pid=\$!; sleep 1; tail -n 5 /workspace/sage_soak_logs/burn_stdout.log 2>/dev/null || true"
echo "Burn launched for ${MINUTES}m with 32 process workers"

