#!/usr/bin/env bash
# Push SAGE to RunPod TCP SSH and run nuclear suite (cgroup workers).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

HOST="${RUNPOD_HOST:-root@157.157.221.29}"
PORT="${RUNPOD_PORT:-33922}"
KEY="${RUNPOD_SSH_KEY:-$HOME/.ssh/id_ed25519}"

echo "Syncing $ROOT -> ${HOST}:${PORT}:/workspace/SAGE"
tar czf - \
  --exclude='.venv' \
  --exclude='.pytest_cache' \
  --exclude='.git' \
  --exclude='artifacts' \
  --exclude='pod_export' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  . | ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -i "$KEY" -p "$PORT" "$HOST" \
  'mkdir -p /workspace/SAGE && find /workspace/SAGE -mindepth 1 -maxdepth 1 -exec rm -rf {} + && tar xzf - -C /workspace/SAGE --no-same-owner --no-same-permissions'

echo "Running pod_nuclear.sh"
ssh -o BatchMode=yes -T -i "$KEY" -p "$PORT" "$HOST" \
  'sed -i "s/\r$//" /workspace/SAGE/scripts/*.sh && bash /workspace/SAGE/scripts/pod_nuclear.sh'
