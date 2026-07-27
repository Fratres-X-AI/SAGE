#!/usr/bin/env bash
set -euo pipefail
sleep 3
rid=$(gh run list --repo Fratres-X-AI/SAGE --branch main --limit 1 --json databaseId --jq '.[0].databaseId')
echo "watching $rid"
gh run watch "$rid" --repo Fratres-X-AI/SAGE --exit-status
gh run list --repo Fratres-X-AI/SAGE --limit 4
