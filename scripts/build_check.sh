#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$REPO_ROOT/dist"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

# zipapp はルートを sys.path に追加するため、
# patch_checker/ をサブディレクトリとして置く必要がある
PKGROOT="$TMPDIR/root"
mkdir -p "$PKGROOT"
cp -r "$REPO_ROOT/patch_checker" "$PKGROOT/patch_checker"
rm -f "$PKGROOT/patch_checker/ssh.py"
find "$PKGROOT" -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

python3 -m zipapp \
    "$PKGROOT" \
    -p '/usr/bin/env python3' \
    -o "$REPO_ROOT/dist/patch-checker.pyz" \
    -m 'patch_checker.cli:main'
