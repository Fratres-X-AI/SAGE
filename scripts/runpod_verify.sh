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
python -m pip install -q -e ".[dev]"
python examples/stale_retrieval_agent.py
sage inspect examples/incident.sage.json
sage make-test examples/incident.sage.json --out-dir tests/generated
pytest -q
REMOTE
