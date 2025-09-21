#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$SCRIPT_DIR/bin"

if [ -d "$BIN_DIR" ]; then
  rm -rf "$BIN_DIR"/*
fi

# Ensure repository is up to date
git -C "$SCRIPT_DIR" fetch --all --prune

# Rebuild binaries
"$SCRIPT_DIR/build.sh"
