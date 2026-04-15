#!/usr/bin/env bash
# Build the patched binary for 162_kore_C3I1S3.
# Outputs: kore (in this directory)

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_SRC="/home/ubuntu/anthropic/corpus/kore"
BUILD_TMP="$(mktemp -d)"

cleanup() { rm -rf "$BUILD_TMP"; }
trap cleanup EXIT

cp -r "$SERVER_SRC/." "$BUILD_TMP/"
patch -p1 -d "$BUILD_TMP" < "$SAMPLE_DIR/patch.diff" > /dev/null

(cd "$BUILD_TMP" && make TLS_BACKEND=none \
    CFLAGS="-w -Iinclude/kore -I\$(OBJDIR)" \
    kore -j"$(nproc)" 2>/dev/null)

cp "$BUILD_TMP/kore" "$SAMPLE_DIR/kore"
echo "[+] built: $SAMPLE_DIR/kore"
