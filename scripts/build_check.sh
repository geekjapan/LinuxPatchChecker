#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$REPO_ROOT/dist"

# ssh.py を除外した一時ディレクトリを作成してビルド
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

cp -r "$REPO_ROOT/patch_checker" "$TMPDIR/patch_checker"
rm -f "$TMPDIR/patch_checker/ssh.py"
rm -f "$TMPDIR/patch_checker/__pycache__/ssh.cpython-"*.pyc

python3 -m zipapp \
    "$TMPDIR/patch_checker" \
    -p '/usr/bin/env python3' \
    -o "$REPO_ROOT/dist/patch-checker-check.pyz" \
    -m 'patch_checker.cli:main'
