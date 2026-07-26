#!/usr/bin/env bash
# Pull soak/burn artifacts off RunPod before teardown.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOST="${RUNPOD_HOST:-root@157.157.221.29}"
PORT="${RUNPOD_PORT:-33922}"
KEY="${RUNPOD_SSH_KEY:-$HOME/.ssh/id_ed25519}"
DEST="${ROOT}/pod_export/soak_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$DEST"

echo "Listing remote soak artifacts..."
ssh -o BatchMode=yes -o ConnectTimeout=20 -i "$KEY" -p "$PORT" "$HOST" \
  'ls -lah /workspace/sage_soak_logs 2>/dev/null; du -sh /workspace/sage_soak_logs /workspace/SAGE 2>/dev/null; ls /workspace/sage_soak_logs | wc -l'

echo "Pulling sage_soak_logs -> $DEST"
scp -o BatchMode=yes -i "$KEY" -P "$PORT" -r \
  "$HOST:/workspace/sage_soak_logs" "$DEST/"

# Compact summary for local reading
python3 - <<PY || true
from pathlib import Path
import json
dest = Path(r"""$DEST""")
logs = dest / "sage_soak_logs"
summary = dest / "PULL_SUMMARY.md"
lines = ["# Pod soak pull", "", f"Source: {logs}", ""]
if logs.is_dir():
    statuses = sorted(logs.glob("soak_max_*.status"))
    jsonls = sorted(logs.glob("soak_max_*.jsonl"))
    burns = sorted(logs.glob("soak_burn_*.jsonl"))
    if statuses:
        last = statuses[-1]
        lines += ["## Last status", "```", last.read_text(encoding="utf-8", errors="replace")[-2000:], "```", ""]
    for kind, files in [("soak", jsonls), ("burn", burns)]:
        if not files:
            continue
        f = files[-1]
        ok = fail = 0
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if obj.get("event") == "complete":
                lines += [f"## {kind} complete event", "```json", json.dumps(obj, indent=2), "```", ""]
            if "ok" in obj and obj.get("event") != "complete":
                if obj.get("ok"):
                    ok += 1
                else:
                    fail += 1
        lines.append(f"- `{f.name}`: ok={ok} fail={fail}")
    lines.append("")
    lines.append(f"Files: {len(list(logs.iterdir()))}")
summary.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(summary.read_text(encoding="utf-8"))
PY

echo "DONE pull -> $DEST"
du -sh "$DEST"
ls -lah "$DEST/sage_soak_logs" | head -40
