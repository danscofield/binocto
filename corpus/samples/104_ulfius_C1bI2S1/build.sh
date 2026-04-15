#!/usr/bin/env bash
# Build the patched binary for 104_ulfius_C2I2S1.
# Outputs: ulfius_server (in this directory)

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_SRC="/home/ubuntu/anthropic/corpus/ulfius"
BUILD_TMP="$(mktemp -d)"

cleanup() { rm -rf "$BUILD_TMP"; }
trap cleanup EXIT

cp "$SERVER_SRC/server.c" "$BUILD_TMP/"
patch -p1 -d "$BUILD_TMP" < "$SAMPLE_DIR/patch.diff" > /dev/null

gcc -o "$SAMPLE_DIR/ulfius_server" "$BUILD_TMP/server.c" \
    -I"$SERVER_SRC/include" \
    -I"$SERVER_SRC/build" \
    -L"$SERVER_SRC/build" \
    -lulfius -lorcania -lpthread \
    -Wl,-rpath,"$SERVER_SRC/build"

echo "[+] built: $SAMPLE_DIR/ulfius_server"
