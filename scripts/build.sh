#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
DIST_DIR="$ROOT_DIR/dist"
OUTPUT="$DIST_DIR/audit.sh"

mkdir -p "$DIST_DIR"

cp "$ROOT_DIR/main.sh" "$OUTPUT"
chmod +x "$OUTPUT"

echo "Built: $OUTPUT"
