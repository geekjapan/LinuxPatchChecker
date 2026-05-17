#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$REPO_ROOT/dist"

cd "$REPO_ROOT"
shiv \
    -e 'patch_checker.cli:main' \
    -o "$REPO_ROOT/dist/patch-checker-ssh.pyz" \
    --reproducible \
    ".[scan]"
