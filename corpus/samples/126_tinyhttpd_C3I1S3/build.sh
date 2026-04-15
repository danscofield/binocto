#!/usr/bin/env bash
# Build the patched binary for 126_tinyhttpd_C3I1S3.
# Outputs: httpd (in this directory)

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_SRC="/home/ubuntu/anthropic/corpus/tinyhttpd"
BUILD_TMP="$(mktemp -d)"

cleanup() { rm -rf "$BUILD_TMP"; }
trap cleanup EXIT

cp "$SERVER_SRC/httpd.c" "$BUILD_TMP/"
patch -p1 -d "$BUILD_TMP" < "$SAMPLE_DIR/patch.diff" > /dev/null
gcc -o "$SAMPLE_DIR/httpd" "$BUILD_TMP/httpd.c" -lpthread

echo "[+] built: $SAMPLE_DIR/httpd"
