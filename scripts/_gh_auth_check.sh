#!/usr/bin/env bash
set -euo pipefail
gh auth status
echo "user=$(gh api user --jq .login)"
gh api orgs/Fratres-X-AI --jq .login
gh api user/orgs --jq '.[].login'
