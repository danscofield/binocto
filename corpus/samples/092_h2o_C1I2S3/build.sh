#!/usr/bin/env bash
# Build the patched binary for 092_h2o_C1I2S3.
# Outputs: h2o (in this directory)

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_SRC="/home/ubuntu/anthropic/corpus/h2o"
BUILD_TMP="$(mktemp -d)"

cleanup() { rm -rf "$BUILD_TMP"; }
trap cleanup EXIT

cp -r "$SERVER_SRC" "$BUILD_TMP/src"
patch -p1 -d "$BUILD_TMP/src" < "$SAMPLE_DIR/patch.diff" > /dev/null
mkdir -p "$BUILD_TMP/build"
cmake -S "$BUILD_TMP/src" -B "$BUILD_TMP/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DWITH_MRUBY=OFF \
    2>/dev/null
make -C "$BUILD_TMP/build" h2o -j"$(nproc)" 2>/dev/null
BINARY=$(find "$BUILD_TMP/build" -name "h2o" -type f | head -1)
cp "$BINARY" "$SAMPLE_DIR/h2o"

echo "[+] built: $SAMPLE_DIR/h2o"
