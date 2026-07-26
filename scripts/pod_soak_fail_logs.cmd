@echo off
"C:\Program Files\Git\bin\bash.exe" -lc "ssh -o BatchMode=yes -i ~/.ssh/id_ed25519 -p 33922 root@157.157.221.29 'f=$(ls -t /workspace/sage_soak_logs/soak_max_*_nuclear_1.log 2>/dev/null | head -1); echo LOG=$f; grep -A20 FAILURES \"$f\" | head -60; echo ---; grep -E \"FAILED|Error|assert\" \"$f\" | tail -20'"
