#!/usr/bin/env bash
set -euo pipefail
gh run list --repo Fratres-X-AI/SAGE --branch main --limit 3
echo "---"
rid=$(gh run list --repo Fratres-X-AI/SAGE --branch main --limit 1 --json databaseId,conclusion,status,url --jq '.[0]')
echo "$rid"
gh run view --repo Fratres-X-AI/SAGE "$(echo "$rid" | jq -r .databaseId)" --json jobs --jq '.jobs[] | "\(.name): \(.conclusion // .status)"'
