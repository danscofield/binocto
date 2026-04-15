"""Subprocess harness: atomic port allocation + full-stack HTTP test runner."""

from __future__ import annotations

import os
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests
import requests.exceptions

from models import VerifyFailure


# ---------------------------------------------------------------------------
# Atomic port allocation
# ---------------------------------------------------------------------------

_port_lock  = threading.Lock()
_allocated: set[int] = set()
_PORT_RANGE = range(22000, 23000)


def allocate_port() -> int:
    """Atomically find and reserve an available port in 22000-22999."""
    with _port_lock:
        for port in _PORT_RANGE:
            if port in _allocated:
                continue
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("127.0.0.1", port))
                sock.close()
                _allocated.add(port)
                return port
            except OSError:
                continue
    raise RuntimeError("No free port in range 22000-22999")


def release_port(port: int) -> None:
    with _port_lock:
        _allocated.discard(port)


# ---------------------------------------------------------------------------
# Harness data types
# ---------------------------------------------------------------------------

@dataclass
class HTTPRequest:
    method:  str
    path:    str
    body:    Optional[str]       = None
    headers: Dict[str, str]      = field(default_factory=dict)


@dataclass
class HarnessResult:
    success:        bool
    failure_reason: Optional[str]        # VerifyFailure value, or None on success
    responses:      List[Dict]
    marker_found:   bool
    stdout:         str
    stderr:         str


# ---------------------------------------------------------------------------
# Main harness runner
# ---------------------------------------------------------------------------

def subprocess_harness(
    binary:          str,
    args:            List[str],
    port:            int,
    setup_files:     Dict[str, str],      # abs_path → file content
    http_sequence:   List[HTTPRequest],
    marker_path:     Optional[str] = None,    # file whose *existence* = success
    marker_content:  Optional[str] = None,    # or string to find in last response body
    startup_timeout: float = 5.0,
    request_timeout: float = 5.0,
) -> HarnessResult:
    """Run *binary* with *args*, write *setup_files*, fire *http_sequence*,
    then check for *marker_path* or *marker_content* to determine success.

    Failure taxonomy (VerifyFailure):
      SERVER_CRASH     – binary exited before/during requests
      PORT_CONFLICT    – server never accepted connections on *port*
      WRONG_ROUTE      – any request returned 404
      WRONG_TOKEN      – /exec/init path returned 401 or 403
      WRONG_CONFIG_KEY – server ran fine but marker absent (key/value wrong)
    """
    # -- write setup files ---------------------------------------------------
    for path, content in setup_files.items():
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w") as fh:
            fh.write(content)

    # -- clean stale marker --------------------------------------------------
    if marker_path and os.path.exists(marker_path):
        try:
            os.unlink(marker_path)
        except OSError:
            pass

    # -- start server --------------------------------------------------------
    proc = subprocess.Popen(
        [binary, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for the server to accept connections.
    deadline = time.monotonic() + startup_timeout
    ready = False
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            stdout, stderr = proc.communicate()
            return HarnessResult(
                success=False,
                failure_reason=VerifyFailure.SERVER_CRASH,
                responses=[], marker_found=False,
                stdout=stdout.decode(errors="replace"),
                stderr=stderr.decode(errors="replace"),
            )
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.3)
            s.close()
            ready = True
            break
        except (ConnectionRefusedError, OSError):
            time.sleep(0.05)

    if not ready:
        proc.kill()
        stdout, stderr = proc.communicate()
        return HarnessResult(
            success=False,
            failure_reason=VerifyFailure.PORT_CONFLICT,
            responses=[], marker_found=False,
            stdout=stdout.decode(errors="replace"),
            stderr=stderr.decode(errors="replace"),
        )

    # -- fire HTTP sequence --------------------------------------------------
    responses: List[Dict] = []
    failure_reason: Optional[str] = None

    for req in http_sequence:
        if proc.poll() is not None:
            failure_reason = VerifyFailure.SERVER_CRASH
            break
        try:
            url  = f"http://127.0.0.1:{port}{req.path}"
            resp = requests.request(
                req.method, url,
                data=req.body, headers=req.headers,
                timeout=request_timeout,
            )
            entry = {"status": resp.status_code, "body": resp.text[:2000]}
            responses.append(entry)

            if failure_reason is None:
                if resp.status_code == 404:
                    failure_reason = VerifyFailure.WRONG_ROUTE
                elif resp.status_code in (401, 403) and "init" in req.path.lower():
                    failure_reason = VerifyFailure.WRONG_TOKEN

        except requests.exceptions.ConnectionError:
            failure_reason = VerifyFailure.SERVER_CRASH
            break
        except requests.exceptions.Timeout:
            failure_reason = VerifyFailure.SERVER_CRASH
            break

    # Allow async side-effects (e.g. system() writing a file) to land.
    time.sleep(0.4)

    proc.kill()
    try:
        stdout, stderr = proc.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        proc.wait()
        stdout, stderr = b"", b""

    # -- check marker --------------------------------------------------------
    marker_found = False
    if marker_path:
        marker_found = os.path.exists(marker_path)
        if marker_found:
            try:
                os.unlink(marker_path)
            except OSError:
                pass
    elif marker_content and responses:
        marker_found = any(marker_content in r.get("body", "") for r in responses)

    # Infer WRONG_CONFIG_KEY: server ran + route found + no crash, but no effect.
    if not marker_found and failure_reason is None and responses:
        last_status = responses[-1].get("status", 0)
        if last_status in (200, 204):
            failure_reason = VerifyFailure.WRONG_CONFIG_KEY

    success = marker_found and failure_reason is None

    return HarnessResult(
        success=success,
        failure_reason=failure_reason,
        responses=responses,
        marker_found=marker_found,
        stdout=stdout.decode(errors="replace"),
        stderr=stderr.decode(errors="replace"),
    )
