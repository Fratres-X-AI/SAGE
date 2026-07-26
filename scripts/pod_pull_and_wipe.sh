#!/usr/bin/env bash
# Pull all SAGE artifacts from RunPod, then wipe the remote workspace.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
HOST='root@157.157.221.29'
PORT=50333
KEY="${HOME}/.ssh/id_ed25519"
REMOTE='/workspace/SAGE'
LOCAL_PULL="${ROOT}/pod_export"

mkdir -p "${LOCAL_PULL}"

echo "Stopping remote SAGE/python jobs ..."
ssh -o BatchMode=yes -T -p "${PORT}" -i "${KEY}" "${HOST}" 'bash -s' <<'REMOTE'
set +e
pkill -f '/workspace/SAGE' 2>/dev/null || true
pkill -f 'sage train' 2>/dev/null || true
sleep 2
ps aux | grep -E 'SAGE|sage train' | grep -v grep || echo 'no sage procs'
REMOTE

echo "Snapshotting remote tree to ${LOCAL_PULL} ..."
ssh -o BatchMode=yes -T -p "${PORT}" -i "${KEY}" "${HOST}" \
  "cd '${REMOTE}' && tar czf - --warning=no-file-changed --exclude='.venv' --exclude='__pycache__' --exclude='.pytest_cache' --exclude='artifacts/train_corpus' --exclude='artifacts/val_corpus' ." \
  | tar xzf - -C "${LOCAL_PULL}" || true

# Fallback: scp key files if tar still noisy
ssh -o BatchMode=yes -T -p "${PORT}" -i "${KEY}" "${HOST}" 'bash -s' <<'REMOTE'
set -euo pipefail
cd /workspace/SAGE
mkdir -p /tmp/sage_snap/artifacts /tmp/sage_snap/examples /tmp/sage_snap/src
cp -a src examples scripts pyproject.toml README.md tests /tmp/sage_snap/ 2>/dev/null || true
cp -a artifacts/train_metrics.json artifacts/bench.json artifacts/span_cause.pt /tmp/sage_snap/artifacts/ 2>/dev/null || true
cd /tmp/sage_snap && tar czf /tmp/sage_snap.tgz .
REMOTE

scp -P "${PORT}" -i "${KEY}" -o BatchMode=yes \
  "${HOST}:/tmp/sage_snap.tgz" "${LOCAL_PULL}/sage_snap.tgz"
tar xzf "${LOCAL_PULL}/sage_snap.tgz" -C "${LOCAL_PULL}"

mkdir -p "${ROOT}/artifacts"
for f in train_metrics.json bench.json span_cause.pt; do
  if [[ -f "${LOCAL_PULL}/artifacts/${f}" ]]; then
    cp -f "${LOCAL_PULL}/artifacts/${f}" "${ROOT}/artifacts/${f}"
  fi
done
if [[ -f "${LOCAL_PULL}/examples/incident.sage.json" ]]; then
  cp -f "${LOCAL_PULL}/examples/incident.sage.json" "${ROOT}/examples/" || true
fi

echo "Pulled key files:"
ls -la "${ROOT}/artifacts" || true
find "${LOCAL_PULL}" -maxdepth 3 -type f | head -n 60

echo "Wiping remote ${REMOTE} and temp snap ..."
ssh -o BatchMode=yes -T -p "${PORT}" -i "${KEY}" "${HOST}" 'bash -s' <<'REMOTE'
set -euo pipefail
rm -rf /workspace/SAGE /tmp/sage_snap /tmp/sage_snap.tgz
mkdir -p /workspace
echo wiped
ls -la /workspace
REMOTE

echo "Done. Local: pod_export/ + artifacts/. Remote /workspace/SAGE removed."
