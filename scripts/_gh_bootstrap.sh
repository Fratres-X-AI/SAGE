#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
echo "=== git status ==="
git status
echo "=== remotes ==="
git remote -v || true
echo "=== gh auth ==="
gh auth status
echo "=== user ==="
gh api user --jq .login
echo "=== orgs ==="
gh api user/orgs --jq '.[].login' || true
echo "=== org check Fratres-X-AI ==="
gh api orgs/Fratres-X-AI --jq .login || echo "ORG_CHECK_FAILED"
