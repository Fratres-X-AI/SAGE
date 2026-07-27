#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

git add README.md docs/assets/sage-linkedin-hero.png docs/LINKEDIN_LAUNCH.md
git status --short

git commit -m "$(cat <<'EOF'
Polish public launch surface: elite README, LinkedIn hero, launch kit.

EOF
)" || echo "nothing to commit"

git push origin HEAD

echo "Making repo public..."
gh repo edit Fratres-X-AI/SAGE --visibility public --accept-visibility-change-consequences

gh repo view Fratres-X-AI/SAGE --json url,visibility --jq .
echo "DONE"
