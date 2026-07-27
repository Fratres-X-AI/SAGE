#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/docs/assets"
SRC="/c/Users/Besn Daddy/.cursor/projects/c-Users-Besn-Daddy-Desktop-SAGE/assets/sage-linkedin-hero.png"
cp -f "$SRC" "$ROOT/docs/assets/sage-linkedin-hero.png"
ls -la "$ROOT/docs/assets/sage-linkedin-hero.png"
