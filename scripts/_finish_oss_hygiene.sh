#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p .github
cat > .github/dependabot.yml <<'EOF'
version: 2
updates:
  - package-ecosystem: github-actions
    directory: "/"
    schedule:
      interval: weekly
    open-pull-requests-limit: 5
  - package-ecosystem: pip
    directory: "/"
    schedule:
      interval: monthly
    open-pull-requests-limit: 5
EOF

cat > CONTRIBUTING.md <<'EOF'
# Contributing to SAGE

SAGE is a **fail-closed security / forensics** toolkit. PRs that weaken verify defaults, skip quarantine, or treat research as custody will be rejected.

## Setup

```bash
pip install -e ".[dev]"
python scripts/release_check.py
pytest -q
```

## Rules

1. Compact verify before rehydrate (hash binding).
2. Redact / sanitize before hashing or journal append.
3. `--require-signature` must stay pinned-key (no TOFU by default).
4. Keep core stdlib-only; optional extras for sign/attr/train/tui.
5. Do not commit keys, soak logs, or `pod_export/`.
6. Research lives under `sage research *` only.

## PR checklist

- [ ] `python scripts/release_check.py`
- [ ] `pytest -q` green
- [ ] Docs/CHANGELOG updated if user-facing
- [ ] No secrets in the diff
EOF

python - <<'PY'
from pathlib import Path
p = Path(".github/workflows/ci.yml")
text = p.read_text(encoding="utf-8")
if "concurrency:" not in text:
    text = text.replace(
        "pull_request:\n\njobs:",
        "pull_request:\n\nconcurrency:\n  group: ci-${{ github.workflow }}-${{ github.ref }}\n  cancel-in-progress: true\n\njobs:",
    )
    p.write_text(text, encoding="utf-8")
    print("ci concurrency added")
else:
    print("ci concurrency already present")
PY

# Ensure release_check still mentions CONTRIBUTING optionally — skip

git add -A
git status --short

if ! git diff --cached --quiet; then
  git commit -m "$(cat <<'EOF'
Add Dependabot, CONTRIBUTING, and CI concurrency.

EOF
)"
  git push origin HEAD
else
  echo "No hygiene changes to commit"
fi

if ! git rev-parse "v2.1.1" >/dev/null 2>&1; then
  git tag -a "v2.1.1" -m "SAGE 2.1.1 — OSS launch polish (pinned Ed25519, auditor kit)"
  git push origin "v2.1.1"
else
  echo "tag v2.1.1 exists locally"
  git push origin "v2.1.1" || true
fi

NOTES=$(cat <<'EOF'
## SAGE 2.1.1

Pinned Ed25519 verify (TOFU refused), auditor policy/kit, quarantine unpack, release gate, threat-matrix, multi-OS CI.

See CHANGELOG.md for full notes. Install: `pip install -e ".[dev]"`.
EOF
)

if gh release view "v2.1.1" --repo Fratres-X-AI/SAGE >/dev/null 2>&1; then
  echo "release v2.1.1 exists"
else
  gh release create "v2.1.1" \
    --repo Fratres-X-AI/SAGE \
    --title "SAGE 2.1.1" \
    --notes "$NOTES" \
    --latest
fi

# Branch protection — require CI on ubuntu 3.12 as a minimum gate
set +e
gh api --method PUT \
  -H "Accept: application/vnd.github+json" \
  "/repos/Fratres-X-AI/SAGE/branches/main/protection" \
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
bp=$?
set -e
if [[ "$bp" -ne 0 ]]; then
  echo "BRANCH_PROTECTION_SKIPPED (org/plan/admin may block API)"
else
  echo "Branch protection applied on main"
fi

echo "---"
gh release view v2.1.1 --repo Fratres-X-AI/SAGE --json url,tagName,isLatest
gh run list --repo Fratres-X-AI/SAGE --branch main --limit 2
echo "DONE"
