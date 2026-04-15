#!/usr/bin/env bash
# Build the patched binary for 113_seasocks_C2I2S2.
set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_SRC="/home/ubuntu/anthropic/corpus/seasocks"
BUILD_TMP="$(mktemp -d)"

cleanup() { rm -rf "$BUILD_TMP"; }
trap cleanup EXIT

cp -r "$SERVER_SRC/." "$BUILD_TMP/"
# Remove any pre-existing cmake build cache to avoid stale cache errors
rm -rf "$BUILD_TMP/build" "$BUILD_TMP/build_test"
patch -p1 -d "$BUILD_TMP" < "$SAMPLE_DIR/patch.diff" > /dev/null
mkdir -p "$BUILD_TMP/build"
cmake -S "$BUILD_TMP" -B "$BUILD_TMP/build" -DCMAKE_BUILD_TYPE=Release -DUNITTESTS=OFF 2>/dev/null
make -C "$BUILD_TMP/build" -j$(nproc) seasocks_server 2>/dev/null
BINARY=$(find "$BUILD_TMP/build" -name "seasocks_server" -type f | head -1)
cp "$BINARY" "$SAMPLE_DIR/seasocks_server"
echo "[+] built: $SAMPLE_DIR/seasocks_server"
