#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
tar czf - . | ssh -o BatchMode=yes root@157.157.221.29 -p 50333 -i ~/.ssh/id_ed25519 \
  'mkdir -p /workspace/SAGE && tar xzf - -C /workspace/SAGE --no-same-owner --no-same-permissions'
ssh -o BatchMode=yes -T root@157.157.221.29 -p 50333 -i ~/.ssh/id_ed25519 <<'REMOTE'
set -euo pipefail
cd /workspace/SAGE
sed -i 's/\r$//' scripts/*.sh
bash scripts/cgroup_cpus.sh
python -m venv .venv
source .venv/bin/activate
python -m pip install -q -U pip
python -m pip install -q -e ".[all]"
python - <<'PY'
import torch
print({"cuda": torch.cuda.is_available(), "device": torch.cuda.get_device_name(0) if torch.cuda.is_available() else "cpu"})
PY
# Size workers from cgroup quota (not nproc)
CPUS=$(bash scripts/cgroup_cpus.sh)
export OMP_NUM_THREADS="${CPUS}"
export MKL_NUM_THREADS="${CPUS}"
sage train --n-train 5000 --n-val 1000 --epochs 15 --batch-size 128 --out-dir artifacts
sage bench --n 1500 --model artifacts/span_cause.pt --out artifacts/bench.json
sage attribute examples/incident.sage.json --method ensemble --model artifacts/span_cause.pt || true
python examples/stale_retrieval_agent.py
sage attribute examples/incident.sage.json --method ensemble --model artifacts/span_cause.pt
pytest -q
cat artifacts/train_metrics.json
cat artifacts/bench.json
REMOTE
