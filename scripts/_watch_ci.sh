#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
echo "Waiting for workflow run..."
for i in $(seq 1 30); do
  rid=$(gh run list --repo Fratres-X-AI/SAGE --branch main --limit 1 --json databaseId,status,conclusion,name,url --jq '.[0].databaseId // empty')
  if [[ -n "${rid}" ]]; then
    echo "Found run ${rid}"
    gh run list --repo Fratres-X-AI/SAGE --branch main --limit 3
    gh run watch "$rid" --repo Fratres-X-AI/SAGE --exit-status
    exit $?
  fi
  sleep 2
done
echo "No run found" >&2
exit 1
