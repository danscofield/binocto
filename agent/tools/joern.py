"""Joern CPG tools.

Workflow
--------
1. Call ``build_cpg(binary)`` once per binary.  This runs ``joern-parse`` and
   returns the path to the generated ``cpg.bin`` file.  Store the path in
   ``GraphState.joern_cpg``.
2. All subsequent query functions accept ``cpg_path`` as their first argument.
   Each query writes a temporary Scala script and runs it via ``joern --script``,
   or (if a server was started for that CPG) posts to the persistent HTTP server.

Environment variables
---------------------
  JOERN_BIN        path to the ``joern`` executable        (default: "joern")
  JOERN_PARSE_BIN  path to the ``joern-parse`` executable  (default: "joern-parse")

Server mode
-----------
Call ``start_joern_server(cpg_path)`` to start a persistent Joern HTTP server
for a given CPG (avoids per-query JVM startup cost).  Subsequently all queries
via this module are routed through the server automatically.  Call
``stop_joern_server(cpg_path)`` to shut down the server and release the port.
"""

from __future__ import annotations

import ast
import atexit
import hashlib
import logging
import os
import re
import signal
import subprocess
import tempfile
import threading
import time
from typing import Dict, List, Optional, Tuple

import requests as _requests

# Strip ANSI escape codes (colour, bold, reset) from Joern REPL output.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[mK]")

log = logging.getLogger("agent.joern")

JOERN_BIN       = os.environ.get("JOERN_BIN",       "joern")
JOERN_PARSE_BIN = os.environ.get("JOERN_PARSE_BIN", "joern-parse")
JOERN_CACHE_DIR = os.environ.get("JOERN_CACHE_DIR", "/tmp/joern_cache")

_SCRIPT_TIMEOUT = int(os.environ.get("JOERN_TIMEOUT", "120"))

# ---------------------------------------------------------------------------
# Server registry
# ---------------------------------------------------------------------------

# Maps cpg_path → (Popen process, port)
_server_registry: Dict[str, Tuple[subprocess.Popen, int]] = {}
_server_lock = threading.Lock()

_SERVER_STARTUP_TIMEOUT = 90   # seconds — JVM is slow to start
_SERVER_POLL_INTERVAL   = 0.5  # seconds between readiness polls
_IMPORTS = "import scala.math.Ordered.orderingToOrdered\n"


def _kill_proc_group(proc: subprocess.Popen) -> None:
    """Kill the entire process group started by *proc*.

    ``joern`` is a shell wrapper that spawns a JVM child.  Killing only the
    shell (proc.kill()) leaves the JVM orphaned.  Because we launch Joern with
    ``os.setsid``, the shell and all its children share a process group whose
    PGID == proc.pid, so we can nuke the whole group atomically.
    """
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except ProcessLookupError:
        pass  # already dead
    except Exception:
        # Fallback: kill just the shell.
        try:
            proc.kill()
        except Exception:
            pass
    try:
        proc.wait(timeout=5)
    except Exception:
        pass


def _atexit_kill_all_servers() -> None:
    """Kill every registered Joern server when the Python process exits.

    Called automatically via atexit — covers crashes, timeouts, and Ctrl+C.
    """
    with _server_lock:
        entries = list(_server_registry.items())
        _server_registry.clear()

    for cpg_path, (proc, port) in entries:
        log.info("atexit: stopping Joern server for %s (port %d)", cpg_path, port)
        _kill_proc_group(proc)
        try:
            from tools.harness import release_port  # noqa: PLC0415
            release_port(port)
        except Exception:
            pass


atexit.register(_atexit_kill_all_servers)


def kill_stale_joern_servers() -> int:
    """Kill any Joern JVM processes not tracked in _server_registry.

    Call this at the start of a batch run to clean up JVMs orphaned by previous
    crashes or timeouts.  Returns the number of processes killed.

    We search for java processes that have ``ReplBridge`` in their command line
    (the Joern server JVM entry point) rather than the shell wrapper, because
    the shell may already be gone while the JVM child is still running.
    """
    try:
        result = subprocess.run(
            ["pgrep", "-f", "ReplBridge.*--server"],
            capture_output=True, text=True,
        )
        pids = [int(p) for p in result.stdout.split() if p.strip()]
    except Exception:
        return 0

    # PIDs of JVM children spawned by processes we own.
    with _server_lock:
        known_pids = {proc.pid for proc, _ in _server_registry.values()}

    killed = 0
    for pid in pids:
        if pid in known_pids:
            continue
        try:
            # Try to kill via process group (in case shell wrapper is still alive).
            try:
                pgid = os.getpgid(pid)
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except Exception:
                os.kill(pid, signal.SIGKILL)
            log.info("killed stale Joern JVM PID %d", pid)
            killed += 1
        except ProcessLookupError:
            pass
        except Exception as exc:
            log.warning("could not kill PID %d: %s", pid, exc)

    return killed


def start_joern_server(cpg_path: str) -> int:
    """Start a persistent Joern HTTP server for *cpg_path* and return its port.

    Idempotent: if a server is already running for this CPG, returns the
    existing port without starting a new process.

    Multiple CPGs can start their servers in parallel — the lock is only held
    for the fast registry check and the final insertion.  If two callers race
    on the same CPG path, the slower one discards its server and returns the
    winner's port.
    """
    # Fast path — avoid startup work entirely if already running.
    with _server_lock:
        if cpg_path in _server_registry:
            _, port = _server_registry[cpg_path]
            log.info("Joern server already running for %s on port %d", cpg_path, port)
            return port

    # Slow path — all the startup work happens WITHOUT holding the lock so that
    # concurrent analyses of different binaries can start their servers in parallel.
    from tools.harness import allocate_port, release_port  # noqa: PLC0415

    port = allocate_port()
    log.info("Starting Joern server for %s on port %d", cpg_path, port)

    proc = subprocess.Popen(
        [
            JOERN_BIN,
            "--server",
            "--server-host", "127.0.0.1",
            "--server-port", str(port),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        # New process group so we can kill the shell wrapper AND the JVM child
        # together via os.killpg(proc.pid, SIGKILL).
        preexec_fn=os.setsid,
    )

    # Poll for HTTP readiness (no lock held — other CPG startups proceed freely).
    # The correct readiness probe is a POST to /query with a trivial expression.
    deadline = time.monotonic() + _SERVER_STARTUP_TIMEOUT
    ready = False
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            stderr_b = proc.stderr.read()
            release_port(port)
            raise RuntimeError(
                f"Joern server exited unexpectedly during startup:\n"
                f"{stderr_b.decode(errors='replace')[:800]}"
            )
        try:
            r = _requests.post(
                f"http://127.0.0.1:{port}/query",
                json={"query": "1"},
                timeout=2,
            )
            if r.status_code < 500:
                ready = True
                break
        except Exception:
            pass
        time.sleep(_SERVER_POLL_INTERVAL)

    if not ready:
        _kill_proc_group(proc)
        release_port(port)
        raise RuntimeError(
            f"Joern server did not become ready within {_SERVER_STARTUP_TIMEOUT}s "
            f"for CPG {cpg_path}"
        )

    # Load and verify the CPG (still no lock held).
    log.info("Loading CPG %s into Joern server on port %d", cpg_path, port)
    _query_via_server(port, f'importCpg("{cpg_path}")')
    _query_via_server(port, "cpg.metaData.l")

    # Insert under lock — handle the unlikely race where two threads started
    # the same CPG's server simultaneously.
    with _server_lock:
        if cpg_path in _server_registry:
            # Another thread won; discard ours and use theirs.
            _kill_proc_group(proc)
            release_port(port)
            _, port = _server_registry[cpg_path]
            log.info("Joern server race resolved for %s — using port %d", cpg_path, port)
        else:
            _server_registry[cpg_path] = (proc, port)
            log.info("Joern server ready for %s on port %d", cpg_path, port)

    return port


def stop_joern_server(cpg_path: str) -> None:
    """Kill the Joern server for *cpg_path* and release its port.

    No-op if no server is running for this CPG.
    """
    with _server_lock:
        if cpg_path not in _server_registry:
            return
        proc, port = _server_registry.pop(cpg_path)

    log.info("Stopping Joern server for %s (port %d)", cpg_path, port)
    _kill_proc_group(proc)

    from tools.harness import release_port  # noqa: PLC0415
    release_port(port)


_RESULT_POLL_INTERVAL = 0.5   # seconds between result polls
_RESULT_POLL_TIMEOUT  = _SCRIPT_TIMEOUT  # give up after this many seconds

_NOISE_PREFIXES = {
    "executing", "Creating", "Loading", "Overlay", "closing",
    "The graph", "writing", "[INFO", "[WARN", "Warning",
    "scala>", "      |",  # REPL prompts / continuation lines
}


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _filter_noise(raw: str) -> str:
    lines = [
        l for l in _strip_ansi(raw).splitlines()
        if l.strip() and not any(l.strip().startswith(n) for n in _NOISE_PREFIXES)
    ]
    return "\n".join(lines).strip()


# Regex to extract the string VALUE from a REPL result like:
#   val res0: String = "line1\nline2\n..."
_REPL_STRING_RE = re.compile(
    r'val \w+\s*:\s*String\s*=\s*"((?:[^"\\]|\\.)*)"',
    re.DOTALL,
)


def _extract_server_output(stdout: str) -> str:
    """Extract accumulated println output from a server-mode query result.

    In server mode we wrap every query in a block that shadows println with a
    StringBuilder accumulator and returns the buffer as the block result.
    The REPL then shows: val resN: String = "line1\\nline2\\n..."

    We extract and decode that quoted value.  Falls back to _filter_noise when
    the REPL format is not recognised (e.g. non-String result or truncation).
    """
    clean = _strip_ansi(stdout)
    m = _REPL_STRING_RE.search(clean)
    if m:
        raw = m.group(1)
        try:
            # ast.literal_eval correctly decodes \\n → \n, \\" → ", etc.
            return ast.literal_eval(f'"{raw}"').strip()
        except Exception:
            # Manual fallback for the common escapes.
            return (
                raw.replace("\\n", "\n")
                   .replace("\\t", "\t")
                   .replace('\\"', '"')
                   .replace("\\\\", "\\")
                   .strip()
            )
    return _filter_noise(stdout)


def _query_via_server(port: int, body: str) -> str:
    """Submit *body* to the Joern HTTP server on *port* and return the result.

    Joern's HTTP API (scala-repl-pp-server, v4.x):
      POST /query          {"query": "<scala>"} → {"success": true, "uuid": "<id>"}
      GET  /result/<uuid>  → {"success": true, "uuid": "...", "stdout": "..."}

    Polls /result/<uuid> until the result appears or the timeout expires.
    Strips ANSI colour codes and Joern startup noise from stdout.
    """
    base = f"http://127.0.0.1:{port}"

    # 1. Submit query — get UUID.
    submit_resp = _requests.post(
        f"{base}/query",
        json={"query": body},
        timeout=30,
    )
    submit_resp.raise_for_status()
    submit_data = submit_resp.json()

    if not submit_data.get("success", True):
        return f"JOERN_ERROR: submit failed: {submit_data}"

    uuid = submit_data.get("uuid")
    if not uuid:
        # Some versions return the result immediately (no UUID).
        if "stdout" in submit_data:
            return _filter_noise(submit_data["stdout"])
        return f"JOERN_ERROR: no uuid in submit response: {submit_data}"

    # 2. Poll for result.
    deadline = time.monotonic() + _RESULT_POLL_TIMEOUT
    while time.monotonic() < deadline:
        try:
            result_resp = _requests.get(
                f"{base}/result/{uuid}",
                timeout=10,
            )
        except Exception:
            time.sleep(_RESULT_POLL_INTERVAL)
            continue

        if result_resp.status_code == 202:
            # Still processing (some server versions use 202).
            time.sleep(_RESULT_POLL_INTERVAL)
            continue

        result_resp.raise_for_status()
        data = result_resp.json()

        if not data.get("success", True):
            # The server returns status 200 + success:false while the result is
            # still pending (err: "No result (yet?) found for specified UUID").
            # Treat that as "still processing" and keep polling.
            err_msg = data.get("err", "") or ""
            if "No result" in err_msg:
                time.sleep(_RESULT_POLL_INTERVAL)
                continue
            stderr_text = data.get("stderr", "")[:800]
            return f"JOERN_ERROR: {stderr_text}"

        return _filter_noise(data.get("stdout", ""))

    return f"JOERN_ERROR: result not available after {_RESULT_POLL_TIMEOUT}s (uuid={uuid})"


_CPG_FILENAME  = "cpg.bin"
_QUERY_PREFIX  = "q_"


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

def _binary_hash(binary: str) -> str:
    """SHA-256 of the binary content, truncated to 20 hex chars."""
    h = hashlib.sha256()
    with open(binary, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:20]


def _query_hash(body: str) -> str:
    return hashlib.sha256(body.encode()).hexdigest()[:20]


def _cache_dir_for_binary(binary: str) -> str:
    d = os.path.join(JOERN_CACHE_DIR, _binary_hash(binary))
    os.makedirs(d, exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# CPG build  (cached by binary hash)
# ---------------------------------------------------------------------------

def build_cpg(binary: str) -> str:
    """Return path to a Ghidra CPG for *binary*, building it if not cached.

    The CPG is stored at  $JOERN_CACHE_DIR/<binary_hash>/cpg.bin.
    Subsequent calls for the same binary return immediately.
    """
    cache_dir = _cache_dir_for_binary(binary)
    cpg_path  = os.path.join(cache_dir, _CPG_FILENAME)

    if os.path.exists(cpg_path):
        log.info("CPG cache hit  %s", cpg_path)
        return cpg_path

    log.info("building CPG for %s → %s", binary, cpg_path)
    result = subprocess.run(
        [JOERN_PARSE_BIN, binary, "--output", cpg_path, "--language", "ghidra"],
        capture_output=True, text=True, timeout=600,
    )
    if result.returncode != 0:
        raise RuntimeError(f"joern-parse failed:\n{result.stderr[:1000]}")
    return cpg_path


# ---------------------------------------------------------------------------
# Script runner  (query results cached by script body hash)
# ---------------------------------------------------------------------------

def _run_script(cpg_path: str, body: str) -> str:
    """Run a Joern script against *cpg_path*, caching the result to disk.

    Cache key: SHA-256 of the script body.  Cache lives alongside the CPG so
    it is automatically scoped per binary.

    If a Joern server is running for this CPG (see ``start_joern_server``),
    the query is sent over HTTP (no per-query JVM startup overhead).
    Otherwise falls back to launching a subprocess.
    """
    cache_dir  = os.path.dirname(cpg_path)
    cache_file = os.path.join(cache_dir, f"{_QUERY_PREFIX}{_query_hash(body)}.txt")

    if os.path.exists(cache_file):
        cached = open(cache_file).read()
        if cached and not cached.startswith("JOERN_ERROR:"):
            log.info("query cache hit  %s", os.path.basename(cache_file))
            return cached
        # Stale error or empty result from a previous failed run — invalidate and re-run.
        log.info("Invalidating stale cache %s", os.path.basename(cache_file))
        os.unlink(cache_file)

    log.info("running Joern query  cache=%s", os.path.basename(cache_file))
    log.debug("query body:\n%s", body.strip())

    # --- server mode --------------------------------------------------------
    with _server_lock:
        server_entry = _server_registry.get(cpg_path)

    if server_entry is not None:
        _, port = server_entry
        # The Joern HTTP API only captures the last REPL expression's VALUE —
        # println() side effects write to the server process's stdout and are
        # invisible to the caller.  We redirect output to a per-query temp file
        # using a PrintWriter (__pout), then read the file after the query.
        #
        # Implementation: sequential REPL statements (no block wrapper) because
        # the Joern server rejects multi-statement blocks preceded by imports.
        #   1. Declare __pout pointing to a UUID temp file
        #   2. Substitute "println(" → "__pout.println(" in the body
        #   3. Flush + close __pout
        #   4. Read and return the temp file contents
        import uuid as _uuid
        tmp_path = f"/tmp/.joern_q_{_uuid.uuid4().hex}.txt"
        adapted = body.replace("println(", "__pout.println(")
        # Wrap in try/catch/finally so:
        #   - exceptions are captured to the file instead of silently swallowed
        #   - __pout is always flushed/closed (file always exists after the query)
        server_body = (
            # import as a plain top-level statement (not wrapped in a block)
            # so comparison operators on Int/Long work in agent-written queries
            f'import scala.math.Ordered.orderingToOrdered\n'
            f'val __pout = new java.io.PrintWriter('
            f'new java.io.FileWriter("{tmp_path}"))\n'
            f'try {{\n'
            f'{adapted}\n'
            f'}} catch {{ case __e: Throwable => __e.printStackTrace(__pout) }}\n'
            f'finally {{ __pout.flush(); __pout.close() }}\n'
        )
        log.debug("server_body:\n%s", server_body)
        srv_result = _query_via_server(port, server_body)
        log.debug("server response: %s", srv_result[:300] if srv_result else "(empty)")
        if srv_result.startswith("JOERN_ERROR:"):
            log.warning("server query rejected: %s", srv_result[:300])
            output = srv_result
        else:
            try:
                with open(tmp_path) as _fh:
                    raw_out = _fh.read().strip()
                # If the Scala body threw, the file contains a Java stack trace.
                if raw_out.startswith(("java.", "scala.", "Exception", "Error")):
                    log.warning("server query threw exception:\n%s", raw_out[:500])
                    output = f"JOERN_ERROR: {raw_out[:400]}"
                else:
                    output = raw_out
            except FileNotFoundError:
                # __pout constructor itself failed — log the server response for diagnosis.
                log.warning(
                    "server query: temp file not created (FileWriter failed?)\n"
                    "  body[:200]: %s\n  server_response: %s",
                    server_body[:200], srv_result[:200],
                )
                output = ""
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    else:
        # --- subprocess fallback --------------------------------------------
        # subprocess captures println() correctly via stdout.
        script = f'{_IMPORTS}@main def exec() = {{\n{body}\n}}\n'
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sc", delete=False) as fh:
            fh.write(script)
            script_path = fh.name

        try:
            result = subprocess.run(
                [JOERN_BIN, cpg_path, "--script", script_path],
                capture_output=True, text=True, timeout=_SCRIPT_TIMEOUT,
            )
            if result.returncode != 0:
                return f"JOERN_ERROR: {result.stderr[:800]}"

            output = _filter_noise(result.stdout)
        finally:
            os.unlink(script_path)

    # Never cache error or empty results — they may be transient (server restart, timeout,
    # or println capture failure before the temp-file fix was applied).
    if output and not output.startswith("JOERN_ERROR:"):
        with open(cache_file, "w") as fh:
            fh.write(output)

    return output


# ---------------------------------------------------------------------------
# Query functions
# ---------------------------------------------------------------------------

def find_call_sites(cpg_path: str, function_names: List[str]) -> str:
    """Return newline-delimited records for call sites of the given function names.

    Each line: CALL|<function>|<caller>|<addr_decimal>
    (In Ghidra CPGs, lineNumber holds the virtual address as a decimal integer.)
    """
    names_scala = ", ".join(f'"{n}"' for n in function_names)
    body = f"""
  cpg.call.nameExact({names_scala}).foreach {{ c =>
    val callerName = scala.util.Try(c.method.name).getOrElse("UNKNOWN")
    println("CALL|" + c.name + "|" + callerName + "|" + c.lineNumber.getOrElse(-1))
  }}
"""
    return _run_script(cpg_path, body)


def function_call_sequence(cpg_path: str, function_name: str) -> str:
    """List all calls in *function_name* sorted by address.

    In a Ghidra CPG this is the most useful view of a function: each line is
    an instruction or call with its virtual address, letting the agent read the
    control flow and identify compare/goto patterns that guard other calls.

    Output lines: [<addr_decimal>] <call_name>  <code>
    """
    body = f"""
  cpg.method.nameExact("{function_name}").l match {{
    case Nil => println("FUNCTION_NOT_FOUND: {function_name}")
    case methods =>
      methods.foreach {{ m =>
        println(s"=== ${{m.name}}  params=${{m.parameter.size}} ===")
        m.call.sortBy(_.lineNumber.getOrElse(-1)).foreach(c =>
          println(s"  [${{c.lineNumber.getOrElse(-1)}}] ${{c.name}}  ${{c.code.take(80)}}")
        )
      }}
  }}
"""
    return _run_script(cpg_path, body)


def trace_condition(cpg_path: str, addr: str) -> str:
    """Show the call sequence of the function containing the node at *addr*.

    Also shows the same for each direct caller, so the agent can see both
    internal guards (compares before the sink inside the same function) and
    external gates (conditions in the caller that gate the call entirely).

    *addr* accepts hex ("0x401234") or decimal.
    """
    try:
        addr_dec = int(addr, 16) if str(addr).startswith("0x") else int(addr)
    except (ValueError, TypeError):
        addr_dec = -1

    body = f"""
  val targetAddr = {addr_dec}
  val hits = cpg.call.filter(_.lineNumber.contains(targetAddr)).l
  if (hits.isEmpty) {{
    println(s"NO_CALL_AT $targetAddr")
  }} else {{
    val target = hits.head
    val fnNameOpt = scala.util.Try(target.method.name).toOption
    fnNameOpt match {{
      case None =>
        println(s"NO_METHOD_AT $targetAddr")
      case Some(fnName) =>
        val fn = target.method

        // --- calls inside the containing function (internal guards) ---
        println(s"=== CONTAINING_FN: ${{fnName}} ===")
        fn.call.sortBy(_.lineNumber.getOrElse(-1)).foreach(c =>
          println(s"  [${{c.lineNumber.getOrElse(-1)}}] ${{c.name}}  ${{c.code.take(80)}}")
        )

        // --- callers and their context around the call site ---
        val callerFns = cpg.method.nameExact(fnName).caller.l
        callerFns.take(3).foreach {{ callerFn =>
          println(s"=== CALLER_FN: ${{callerFn.name}} ===")
          callerFn.call.sortBy(_.lineNumber.getOrElse(-1)).foreach(c =>
            println(s"  [${{c.lineNumber.getOrElse(-1)}}] ${{c.name}}  ${{c.code.take(80)}}")
          )
        }}
    }}
  }}
"""
    return _run_script(cpg_path, body)


def forward_taint(cpg_path: str, source_patterns: List[str], sink_fn: str) -> str:
    """Check whether data flows from calls matching *source_patterns* to *sink_fn*.

    Uses Joern's reachableByFlows.  In a Ghidra CPG the flow elements are
    register/memory references (e.g. RAX, RDI) rather than named variables,
    but the existence of a flow path is still meaningful.
    """
    sources_scala = ", ".join(f'"{s}"' for s in source_patterns)
    body = f"""
  val sinkArgs = cpg.call.nameExact("{sink_fn}").argument.l
  if (sinkArgs.isEmpty) {{
    println("NO_SINK_FOUND: {sink_fn}")
  }} else {{
    val sourceArgs = cpg.call.nameExact({sources_scala}).argument.l
    if (sourceArgs.isEmpty) {{
      println("NO_SOURCES_FOUND")
    }} else {{
      val flows = sinkArgs.reachableByFlows(sourceArgs).take(3).l
      println(s"FLOW_COUNT: ${{flows.length}}")
      flows.foreach(f =>
        println("  PATH: " + f.elements.take(6).map(e => s"${{e.code}}@${{e.lineNumber.getOrElse(-1)}}").mkString(" -> "))
      )
    }}
  }}
"""
    return _run_script(cpg_path, body)


def get_callers(cpg_path: str, function_name: str) -> str:
    """List all functions that call *function_name*, with call-site addresses."""
    body = f"""
  cpg.call.nameExact("{function_name}").foreach {{ c =>
    val callerName = scala.util.Try(c.method.name).getOrElse("UNKNOWN")
    println(s"${{callerName}} @ ${{c.lineNumber.getOrElse(-1)}}")
  }}
"""
    return _run_script(cpg_path, body)


def get_callees(cpg_path: str, function_name: str) -> str:
    """List all non-operator functions called by *function_name*."""
    body = f"""
  cpg.method.nameExact("{function_name}").call
    .filter(c => !c.name.startsWith("<operator>"))
    .nameNot("<BAD-Instruction>")
    .foreach(c => println(s"${{c.name}} @ ${{c.lineNumber.getOrElse(-1)}}"))
"""
    return _run_script(cpg_path, body)


def decompile_function(cpg_path: str, function_name: str) -> str:
    """Show the call sequence of *function_name* (assembly-level, Ghidra CPG).

    Filters out pure operator nodes to focus on meaningful calls.
    Same as function_call_sequence but aliased for node compatibility.
    """
    return function_call_sequence(cpg_path, function_name)


def get_variable_defs(cpg_path: str, variable_name: str) -> str:
    """Search for *variable_name* as a substring in call code across the CPG.

    In a Ghidra CPG there are no named C variables; this searches string
    literals and call arguments for the name (useful for config key names,
    flag strings like '--exec-mode', route paths like '/exec').
    """
    body = f"""
  val pattern = "{variable_name}"
  cpg.call
    .filter(c => c.code.contains(pattern) || c.argument.code(pattern).nonEmpty)
    .take(20)
    .foreach {{ c =>
      val callerName = scala.util.Try(c.method.name).getOrElse("UNKNOWN")
      println(s"  ${{callerName}} @ ${{c.lineNumber.getOrElse(-1)}}: ${{c.code.take(100)}}")
    }}
"""
    return _run_script(cpg_path, body)


def raw_query(cpg_path: str, scala_body: str) -> str:
    """Run an arbitrary CPGql expression.

    *scala_body* is inserted verbatim inside the @main def after importCpg().
    Use this as a last resort when the typed helpers above are insufficient.
    """
    return _run_script(cpg_path, scala_body)
