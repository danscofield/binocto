#!/usr/bin/env bash
# Build the patched binary for 005_darkhttpd_C1I2S2.
# Outputs: darkhttpd (in this directory)

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_SRC="/home/ubuntu/anthropic/corpus/darkhttpd"
BUILD_TMP="$(mktemp -d)"

cleanup() { rm -rf "$BUILD_TMP"; }
trap cleanup EXIT

cp "$SERVER_SRC/darkhttpd.c" "$BUILD_TMP/"
patch -p1 -d "$BUILD_TMP" < "$SAMPLE_DIR/patch.diff" > /dev/null
gcc -o "$SAMPLE_DIR/darkhttpd" "$BUILD_TMP/darkhttpd.c"

echo "[+] built: $SAMPLE_DIR/darkhttpd"
