#!/usr/bin/env bash
# Build the patched binary for 157_merecat_C3I2S3.
# Outputs: merecat (in this directory)

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_SRC="/home/ubuntu/anthropic/corpus/merecat"
BUILD_TMP="$(mktemp -d)"

cleanup() { rm -rf "$BUILD_TMP"; }
trap cleanup EXIT

cp -r "$SERVER_SRC/." "$BUILD_TMP/"
patch -p1 -d "$BUILD_TMP" < "$SAMPLE_DIR/patch.diff" > /dev/null
(cd "$BUILD_TMP" && make -j$(nproc) 2>/dev/null)

BINARY=$(find "$BUILD_TMP" -name "merecat" -type f -not -path "*/.git/*" | grep -v '\.o$' | head -1)
cp "$BINARY" "$SAMPLE_DIR/merecat"

echo "[+] built: $SAMPLE_DIR/merecat"
