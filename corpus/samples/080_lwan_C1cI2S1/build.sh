#!/usr/bin/env bash
# Build the patched binary for 080_lwan_C3I2S1.
# Outputs: lwan (in this directory)

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_SRC="/home/ubuntu/anthropic/corpus/lwan"
BUILD_TMP="$(mktemp -d)"

cleanup() { rm -rf "$BUILD_TMP"; }
trap cleanup EXIT

cp -r "$SERVER_SRC" "$BUILD_TMP/src"
patch -p1 -d "$BUILD_TMP/src" < "$SAMPLE_DIR/patch.diff" > /dev/null
mkdir -p "$BUILD_TMP/build"
cmake -S "$BUILD_TMP/src" -B "$BUILD_TMP/build" -DCMAKE_BUILD_TYPE=Release 2>/dev/null
make -C "$BUILD_TMP/build" lwan -j$(nproc) 2>/dev/null
BINARY=$(find "$BUILD_TMP/build" -name "lwan" -type f | head -1)
cp "$BINARY" "$SAMPLE_DIR/lwan"

echo "[+] built: $SAMPLE_DIR/lwan"
