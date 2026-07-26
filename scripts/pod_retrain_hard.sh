#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
tar czf - \
  src pyproject.toml scripts examples tests README.md \
  | ssh -o BatchMode=yes root@157.157.221.29 -p 50333 -i ~/.ssh/id_ed25519 \
  'mkdir -p /workspace/SAGE && tar xzf - -C /workspace/SAGE --no-same-owner --no-same-permissions'
ssh -o BatchMode=yes -T root@157.157.221.29 -p 50333 -i ~/.ssh/id_ed25519 'bash -s' <<'REMOTE'
set -euo pipefail
cd /workspace/SAGE
sed -i 's/\r$//' scripts/*.sh || true
source .venv/bin/activate
export PYTHONUNBUFFERED=1
python -m pip install -q -e ".[all]"
CPUS=$(bash scripts/cgroup_cpus.sh)
export OMP_NUM_THREADS="${CPUS}"
export MKL_NUM_THREADS="${CPUS}"
echo "device check:"; python -c 'import torch; print(torch.cuda.is_available(), torch.cuda.get_device_name(0) if torch.cuda.is_available() else "cpu")'
sage train --n-train 6000 --n-val 1200 --epochs 20 --batch-size 128 --out-dir artifacts
python - <<'PY'
import json
from sage.attribution.bench import run_benchmark
payload = run_benchmark(n=2000, seed=123, model_path='artifacts/span_cause.pt', out_path='artifacts/bench.json')
print(json.dumps(payload, indent=2))
PY
python examples/stale_retrieval_agent.py
sage attribute examples/incident.sage.json --method ensemble --model artifacts/span_cause.pt
pytest -q
REMOTE
mkdir -p artifacts
scp -P 50333 -i ~/.ssh/id_ed25519 -o BatchMode=yes \
  root@157.157.221.29:/workspace/SAGE/artifacts/train_metrics.json \
  root@157.157.221.29:/workspace/SAGE/artifacts/bench.json \
  root@157.157.221.29:/workspace/SAGE/artifacts/span_cause.pt \
  artifacts/
