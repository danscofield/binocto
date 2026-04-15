#!/usr/bin/env bash
# Build the patched binary for 136_mongoose_C2I2S3.
# Outputs: mongoose_server (in this directory)

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_SRC="/home/ubuntu/anthropic/corpus/mongoose"
BUILD_TMP="$(mktemp -d)"

cleanup() { rm -rf "$BUILD_TMP"; }
trap cleanup EXIT

cp "$SERVER_SRC/server.c" "$BUILD_TMP/"
cp "$SERVER_SRC/mongoose.c" "$BUILD_TMP/"
cp "$SERVER_SRC/mongoose.h" "$BUILD_TMP/"
patch -p1 -d "$BUILD_TMP" < "$SAMPLE_DIR/patch.diff" > /dev/null
gcc -o "$SAMPLE_DIR/mongoose_server" "$BUILD_TMP/server.c" "$BUILD_TMP/mongoose.c" \
    -I"$BUILD_TMP" -DMG_ENABLE_DIRLIST=1

echo "[+] built: $SAMPLE_DIR/mongoose_server"
