#!/usr/bin/env bash
# Build the patched binary for 072_lighttpd_C3I3S1.
# Outputs: lighttpd (in this directory)

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_SRC="/home/ubuntu/anthropic/corpus/lighttpd"
BUILD_TMP="$(mktemp -d)"

cleanup() { rm -rf "$BUILD_TMP"; }
trap cleanup EXIT

cp -r "$SERVER_SRC" "$BUILD_TMP/src"
patch -p1 -d "$BUILD_TMP/src" < "$SAMPLE_DIR/patch.diff" > /dev/null
mkdir -p "$BUILD_TMP/build"
cmake -S "$BUILD_TMP/src" -B "$BUILD_TMP/build" \
    -DCMAKE_BUILD_TYPE=Release -DWITH_PCRE2=OFF -DWITH_ZLIB=OFF \
    > /dev/null 2>&1
make -C "$BUILD_TMP/build" -j$(nproc) lighttpd > /dev/null 2>&1
cp "$BUILD_TMP/build/build/lighttpd" "$SAMPLE_DIR/lighttpd"
chmod +x "$SAMPLE_DIR/lighttpd"

echo "[+] built: $SAMPLE_DIR/lighttpd"
