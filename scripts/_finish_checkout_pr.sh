#!/usr/bin/env bash
set -uo pipefail
REPO=Fratres-X-AI/SAGE
n=1
echo "Waiting PR #$n"
for i in $(seq 1 90); do
  out=$(gh pr checks "$n" --repo "$REPO" 2>&1) || true
  echo "$out" | head -15
  if echo "$out" | grep -qiE 'fail|failure'; then
    echo FAILED
    exit 1
  fi
  pending=$(echo "$out" | grep -ci pending || true)
  if [[ "$pending" -eq 0 ]] && echo "$out" | grep -qiE 'pass|success'; then
    gh pr merge "$n" --repo "$REPO" --squash --delete-branch
    break
  fi
  sleep 10
done
sleep 5
rid=$(gh run list --repo "$REPO" --branch main --workflow ci.yml --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch "$rid" --repo "$REPO" --exit-status
gh pr list --repo "$REPO" --state open
git -C "$(dirname "$0")/.." pull --ff-only origin main || true
gh run list --repo "$REPO" --branch main --limit 4
echo DONE
