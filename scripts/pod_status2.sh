#!/usr/bin/env bash
set -euo pipefail
ssh -o BatchMode=yes -T -o ConnectTimeout=15 root@157.157.221.29 -p 50333 -i ~/.ssh/id_ed25519 'bash -s' <<'REMOTE'
set -euo pipefail
ps aux | grep -E 'sage|train|python' | grep -v grep || true
echo '---'
ls -la /workspace/SAGE/artifacts 2>/dev/null || echo no_artifacts
echo '---'
ls /workspace/SAGE/artifacts/train_corpus 2>/dev/null | wc -l || true
ls /workspace/SAGE/artifacts/val_corpus 2>/dev/null | wc -l || true
echo '---'
nvidia-smi --query-gpu=name,utilization.gpu,memory.used --format=csv,noheader 2>/dev/null || true
REMOTE
