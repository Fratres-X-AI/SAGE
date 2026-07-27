#!/usr/bin/env bash
set -uo pipefail
REPO=Fratres-X-AI/SAGE

echo "=== wait main CI ==="
rid=$(gh run list --repo "$REPO" --branch main --workflow ci.yml --limit 1 --json databaseId,status --jq '.[0].databaseId')
gh run watch "$rid" --repo "$REPO" --exit-status || true
gh run list --repo "$REPO" --branch main --workflow ci.yml --limit 2

merge_one() {
  local n="$1"
  echo "=== PR #$n ==="
  # Wait up to ~15 min for checks
  for i in $(seq 1 90); do
    out=$(gh pr checks "$n" --repo "$REPO" 2>&1) || true
    echo "$out" | head -20
    if echo "$out" | grep -qiE 'fail|failure'; then
      echo "FAILED checks on #$n"
      return 1
    fi
    # All lines pass or skip, none pending
    pending=$(echo "$out" | grep -ci pending || true)
    if [[ "$pending" -eq 0 ]] && echo "$out" | grep -qiE 'pass|success'; then
      echo "GREEN #$n — merging"
      gh pr merge "$n" --repo "$REPO" --squash --delete-branch
      return $?
    fi
    # empty checks yet
    sleep 10
  done
  echo "TIMEOUT #$n"
  return 1
}

mapfile -t PRS < <(gh pr list --repo "$REPO" --state open --json number,headRefName --jq '.[] | select(.headRefName|startswith("dependabot/")) | .number')
echo "PRs: ${PRS[*]:-none}"
for n in "${PRS[@]:-}"; do
  [[ -z "${n:-}" ]] && continue
  merge_one "$n" || echo "skip #$n"
done

# After merges, wait final main CI
sleep 5
rid=$(gh run list --repo "$REPO" --branch main --workflow ci.yml --limit 1 --json databaseId --jq '.[0].databaseId')
echo "final watch $rid"
gh run watch "$rid" --repo "$REPO" --exit-status
gh pr list --repo "$REPO" --state open
gh run list --repo "$REPO" --limit 6
echo "release=$(gh release view v2.1.1 --repo "$REPO" --json url --jq .url)"
echo "DONE"
