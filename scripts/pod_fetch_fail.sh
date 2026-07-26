#!/usr/bin/env bash
set -euo pipefail
ssh -o BatchMode=yes -i ~/.ssh/id_ed25519 -p 33922 root@157.157.221.29 <<'EOF'
f=$(ls -t /workspace/sage_soak_logs/soak_max_*_nuclear_1.log 2>/dev/null | head -1)
echo "LOG=$f"
if [[ -n "$f" ]]; then
  grep -n "FAILURES\|FAILED\|Error\|assert\|too slow\|FileNotFound\|ChainIntegrity" "$f" | tail -40
  echo "---- tail ----"
  tail -n 50 "$f"
fi
EOF
