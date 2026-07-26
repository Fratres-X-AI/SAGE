#!/usr/bin/env bash
set -euo pipefail
ssh -o BatchMode=yes -T -o ConnectTimeout=20 root@157.157.221.29 -p 50333 -i ~/.ssh/id_ed25519 'bash -s' <<'REMOTE'
set -euo pipefail
cd /workspace/SAGE
source .venv/bin/activate
export PYTHONUNBUFFERED=1
CPUS=$(bash scripts/cgroup_cpus.sh)
export OMP_NUM_THREADS="${CPUS}"
export MKL_NUM_THREADS="${CPUS}"
echo "CPUS=${CPUS}"
python - <<'PY'
import json
from pathlib import Path
print(Path('artifacts/train_metrics.json').read_text())
PY
# Fast in-memory bench (avoid rewriting huge corpora)
python - <<'PY'
import json
from sage.attribution.bench import run_benchmark
payload = run_benchmark(n=1500, seed=99, model_path='artifacts/span_cause.pt', out_path='artifacts/bench.json')
print(json.dumps(payload, indent=2))
PY
python examples/stale_retrieval_agent.py
sage attribute examples/incident.sage.json --method ensemble --model artifacts/span_cause.pt
pytest -q
REMOTE

# Pull artifacts home
mkdir -p '/c/Users/Besn Daddy/Desktop/SAGE/artifacts'
scp -P 50333 -i ~/.ssh/id_ed25519 -o BatchMode=yes \
  'root@157.157.221.29:/workspace/SAGE/artifacts/train_metrics.json' \
  'root@157.157.221.29:/workspace/SAGE/artifacts/bench.json' \
  'root@157.157.221.29:/workspace/SAGE/artifacts/span_cause.pt' \
  '/c/Users/Besn Daddy/Desktop/SAGE/artifacts/'
