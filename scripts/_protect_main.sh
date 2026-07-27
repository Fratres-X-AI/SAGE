#!/usr/bin/env bash
set -euo pipefail
# Note: no leading slash — Git Bash mangles /repos/... as a filesystem path.
gh api --method PUT \
  -H "Accept: application/vnd.github+json" \
  "repos/Fratres-X-AI/SAGE/branches/main/protection" \
  --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "test (ubuntu-latest, 3.12)"
    ]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": null,
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
echo "Branch protection OK"
gh api "repos/Fratres-X-AI/SAGE/branches/main/protection" --jq '{strict: .required_status_checks.strict, contexts: .required_status_checks.contexts}'
