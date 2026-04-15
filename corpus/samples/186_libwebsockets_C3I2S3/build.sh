#!/usr/bin/env bash
# Build the patched binary for 186_libwebsockets_C3I2S3.
# Outputs: lws_server (in this directory)

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_SRC="/home/ubuntu/anthropic/corpus/libwebsockets"
LWS_BUILD="${SERVER_SRC}/build"
BUILD_TMP="$(mktemp -d)"

cleanup() { rm -rf "$BUILD_TMP"; }
trap cleanup EXIT

cp "$SERVER_SRC/server.c" "$BUILD_TMP/"
patch -p1 -d "$BUILD_TMP" < "$SAMPLE_DIR/patch.diff" > /dev/null

gcc -o "$SAMPLE_DIR/lws_server" "$BUILD_TMP/server.c" \
    -I"${LWS_BUILD}/include" \
    -L"${LWS_BUILD}/lib" \
    -lwebsockets \
    -Wl,-rpath,"${LWS_BUILD}/lib"

echo "[+] built: $SAMPLE_DIR/lws_server"
