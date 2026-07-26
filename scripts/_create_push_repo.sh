#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -d .git ]]; then
  git init -b main
fi

if ! gh repo view Fratres-X-AI/SAGE >/dev/null 2>&1; then
  echo "Creating private repo Fratres-X-AI/SAGE ..."
  gh repo create Fratres-X-AI/SAGE --private --description "Fail-closed agent incident forensics (SAGE)" --disable-wiki
else
  echo "Repo Fratres-X-AI/SAGE already exists"
fi

if git remote get-url origin >/dev/null 2>&1; then
  git remote set-url origin "https://github.com/Fratres-X-AI/SAGE.git"
else
  git remote add origin "https://github.com/Fratres-X-AI/SAGE.git"
fi

git add -A
git status --short | head -100

if git diff --cached --quiet; then
  if git rev-parse HEAD >/dev/null 2>&1; then
    echo "Working tree clean; pushing existing commits"
  else
    echo "ERROR: nothing to commit and no HEAD" >&2
    exit 1
  fi
else
  git commit -m "$(cat <<'EOF'
Initial commit: SAGE 2.1.1 agent incident forensics toolkit.

Fail-closed custody path with pack v2, quarantine unpack, pinned Ed25519,
auditor kit, threat-matrix gates, and multi-OS CI.
EOF
)"
fi

git push -u origin HEAD
echo "PUSHED"
gh repo view Fratres-X-AI/SAGE --json url,visibility,defaultBranchRef --jq .
