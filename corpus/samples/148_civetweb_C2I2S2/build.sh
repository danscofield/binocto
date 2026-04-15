#!/usr/bin/env bash
# Build the patched binary for 148_civetweb_C2I2S2.
set -euo pipefail
SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_SRC="/home/ubuntu/anthropic/corpus/civetweb"
BUILD_TMP="$(mktemp -d)"
cleanup() { rm -rf "$BUILD_TMP"; }
trap cleanup EXIT
cp -r "$SERVER_SRC" "$BUILD_TMP/src"
patch -p1 -d "$BUILD_TMP/src" < "$SAMPLE_DIR/patch.diff" > /dev/null
mkdir -p "$BUILD_TMP/build"
cmake -S "$BUILD_TMP/src" -B "$BUILD_TMP/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCIVETWEB_BUILD_TESTING=OFF \
    -DCIVETWEB_ENABLE_CXX=OFF \
    2>/dev/null
make -C "$BUILD_TMP/build" -j$(nproc) 2>/dev/null
BINARY=$(find "$BUILD_TMP/build" -name "civetweb" -type f | head -1)
cp "$BINARY" "$SAMPLE_DIR/civetweb"
echo "[+] built: $SAMPLE_DIR/civetweb"
