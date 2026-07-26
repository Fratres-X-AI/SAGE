#!/usr/bin/env bash
set -euo pipefail
ssh -o BatchMode=yes -o ConnectTimeout=15 root@157.157.221.29 -p 50333 -i ~/.ssh/id_ed25519 <<'REMOTE'
set -euo pipefail
echo '=== processes ==='
ps aux | head -n 8
ps aux | grep -E 'pip|python|sage|train' | grep -v grep || true
echo '=== venv ==='
ls -la /workspace/SAGE/.venv/bin 2>/dev/null | head || echo 'no venv'
if [[ -x /workspace/SAGE/.venv/bin/python ]]; then
  /workspace/SAGE/.venv/bin/python - <<'PY'
import sys
print('python', sys.version)
try:
    import torch
    print('torch', torch.__version__, 'cuda', torch.cuda.is_available())
except Exception as e:
    print('torch_import_error', e)
PY
else
  python - <<'PY'
import sys
print('system python', sys.version)
try:
    import torch
    print('torch', torch.__version__, 'cuda', torch.cuda.is_available())
except Exception as e:
    print('torch_import_error', e)
PY
fi
echo '=== artifacts ==='
ls -la /workspace/SAGE/artifacts 2>/dev/null || echo 'no artifacts'
REMOTE
