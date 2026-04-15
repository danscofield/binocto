#!/usr/bin/env bash
# Build the patched binary for 093_onion_C1I3S1.
# Outputs: onion_server (in this directory)

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ONION_SRC="/home/ubuntu/anthropic/corpus/onion"
ONION_BUILD="/home/ubuntu/anthropic/corpus/onion/build"
BUILD_TMP="$(mktemp -d)"

cleanup() { rm -rf "$BUILD_TMP"; }
trap cleanup EXIT

cp "$ONION_SRC/server.c" "$BUILD_TMP/server.c"
patch -p1 "$BUILD_TMP/server.c" < "$SAMPLE_DIR/patch.diff" > /dev/null

gcc -o "$SAMPLE_DIR/onion_server" "$BUILD_TMP/server.c" \
    -I"$ONION_SRC/src" \
    -L"$ONION_BUILD/src/onion" \
    -lonion \
    -Wl,-rpath,"$ONION_BUILD/src/onion"

echo "[+] built: $SAMPLE_DIR/onion_server"
