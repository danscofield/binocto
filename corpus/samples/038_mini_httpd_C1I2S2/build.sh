#!/usr/bin/env bash
# Build the patched binary for 038_mini_httpd_C1I2S2.
set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_SRC="/home/ubuntu/anthropic/corpus/mini_httpd"
BUILD_TMP="$(mktemp -d)"

cleanup() { rm -rf "$BUILD_TMP"; }
trap cleanup EXIT

cp "$SERVER_SRC/mini_httpd.c" "$BUILD_TMP/"
cp "$SERVER_SRC/match.c" "$SERVER_SRC/tdate_parse.c" "$BUILD_TMP/"
cp "$SERVER_SRC/version.h" "$SERVER_SRC/port.h" "$SERVER_SRC/match.h" \
   "$SERVER_SRC/tdate_parse.h" "$SERVER_SRC/mime_encodings.h" \
   "$SERVER_SRC/mime_types.h" "$BUILD_TMP/"
patch -p1 -d "$BUILD_TMP" < "$SAMPLE_DIR/patch.diff" > /dev/null
gcc -o "$SAMPLE_DIR/mini_httpd" \
    "$BUILD_TMP/mini_httpd.c" "$BUILD_TMP/match.c" "$BUILD_TMP/tdate_parse.c" \
    -I"$BUILD_TMP" -DHAVE_SENDFILE -w -lcrypt
echo "[+] built: $SAMPLE_DIR/mini_httpd"
