#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
.venv/Scripts/python.exe scripts/release_check.py
git add -A
git status --short
git commit -m "$(cat <<'EOF'
Relicense to FSL-1.1-ALv2 to protect competing commercial use.

Internal self-host remains free; Competing Use requires a commercial
license. Versions convert to Apache-2.0 after two years.
EOF
)"
git push origin HEAD
git tag -a "v2.2.0" -m "SAGE 2.2.0 — FSL-1.1-ALv2"
git push origin "v2.2.0"
gh release create "v2.2.0" --repo Fratres-X-AI/SAGE --title "SAGE 2.2.0" --notes "$(cat <<'EOF'
## License change

SAGE is now **FSL-1.1-ALv2** (Functional Source License).

- Internal / self-host use: allowed
- Competing commercial product or SaaS: requires a commercial license ([COMMERCIAL.md](https://github.com/Fratres-X-AI/SAGE/blob/main/COMMERCIAL.md))
- Converts to Apache-2.0 two years after each version’s availability

See [LICENSE](https://github.com/Fratres-X-AI/SAGE/blob/main/LICENSE) and [fsl.software](https://fsl.software/).
EOF
)" --latest
echo DONE
