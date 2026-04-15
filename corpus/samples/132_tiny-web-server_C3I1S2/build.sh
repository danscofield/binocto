#!/usr/bin/env bash
# Build the patched binary for 132_tiny-web-server_C3I1S2.
# Outputs: tiny (in this directory)

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_SRC="/home/ubuntu/anthropic/corpus/tiny-web-server"
BUILD_TMP="$(mktemp -d)"

cleanup() { rm -rf "$BUILD_TMP"; }
trap cleanup EXIT

cp "$SERVER_SRC/tiny.c" "$BUILD_TMP/"
patch -p1 -d "$BUILD_TMP" < "$SAMPLE_DIR/patch.diff" > /dev/null
gcc -o "$SAMPLE_DIR/tiny" "$BUILD_TMP/tiny.c"

echo "[+] built: $SAMPLE_DIR/tiny"
