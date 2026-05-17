#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$REPO_ROOT/dist"

python3 -m zipapp \
    "$REPO_ROOT/patch_checker" \
    -p '/usr/bin/env python3' \
    -o "$REPO_ROOT/dist/patch-checker-check.pyz" \
    -m 'patch_checker.cli:main'
