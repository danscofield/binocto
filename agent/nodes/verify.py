"""verify node: attempt to confirm the precondition hypothesis concretely.

Branches on precondition types in the hypothesis, not on corpus taxonomy labels:
  - any "flag" present  → try symbolic angr, fall back to concrete harness
  - any "file" present  → write config file, run harness
  - any "runtime_state" → write config file + run init HTTP request, then harness

Returns updated verify_attempts and verify_failure_reason.
If successful, sets result to an Exploitable SinkResult.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from typing import List, Optional

from models import (
    ConfigurationOption,
    ConfigurationType,
    Sense,
    SinkResult,
    Verdict,
    VerifyFailure,
)
from state import MAX_VERIFY_ATTEMPTS, SinkState
from tools import (
    HTTPRequest,
    angr_concrete_trace,
    angr_find_path,
    subprocess_harness,
    release_port,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _present(hypothesis: List[ConfigurationOption], ctype: ConfigurationType) -> List[ConfigurationOption]:
    return [p for p in hypothesis if p.configuration_type == ctype and p.sense == Sense.present]

def _absent(hypothesis: List[ConfigurationOption], ctype: ConfigurationType) -> List[ConfigurationOption]:
    return [p for p in hypothesis if p.configuration_type == ctype and p.sense == Sense.absent]


def _build_marker(binary: str) -> str:
    """Return a temp-file path to use as the exploitation marker."""
    name = os.path.basename(binary).replace(" ", "_")
    return f"/tmp/verify_marker_{name}"


def _probe_invocation_prefix(binary: str) -> List[str]:
    """Run the binary with no args (and --help as fallback) to detect
    whether it expects a positional directory argument before the flags.

    Most HTTP servers print a usage line like:
        Usage: darkhttpd <wwwroot> [--port N ...]
    when invoked with no arguments.  If a positional <dir>/<root>/<path>
    argument is present in that usage output we prepend /tmp as a stand-in
    docroot; otherwise we return an empty prefix.
    """
    usage = ""
    for probe_args in [[], ["--help"]]:
        try:
            r = subprocess.run(
                [binary, *probe_args],
                capture_output=True, text=True, timeout=3,
            )
            usage = (r.stdout + r.stderr).strip()
            if usage:
                break
        except Exception:
            pass

    # Look for a positional <placeholder> before any --option token on a
    # usage/synopsis line.  Patterns seen in the wild:
    #   darkhttpd <wwwroot> [--port …]
    #   mongoose  <document_root> [options]
    #   thttpd    <dir> [-p port]
    if re.search(
        r"(?i)usage[^\n]*?<(?:www|doc(?:ument)?[_-]?root|root|dir|path|web[_-]?root)[^>]*>",
        usage,
    ):
        return ["/tmp"]

    return []


# ---------------------------------------------------------------------------
# Strategy implementations
# ---------------------------------------------------------------------------

def _verify_cli_flags(
    state: SinkState,
    flag_opts: List[ConfigurationOption],
    sink_addr: int,
    port: int,
    input_path: dict,
) -> Optional[str]:
    """
    Try symbolic angr first; on timeout/UNSAT fall back to concrete harness.
    Returns None on success, VerifyFailure value on failure.
    """
    binary = state["binary"]

    # Build argv: concrete flag args + symbolic stdin
    concrete_args = [p.configuration_parameter for p in flag_opts]

    # --- symbolic attempt ---
    sym_result = angr_find_path(
        binary=binary,
        find_addrs=[sink_addr],
        symbolic_args=concrete_args + ["sym"],  # last slot is request payload
        timeout=60,
    )
    if sym_result.sat:
        return None   # success

    # --- concrete harness fallback ---
    route  = input_path.get("route", "/exec")
    param  = input_path.get("param", "cmd")
    method = input_path.get("method", "GET").upper()
    marker = _build_marker(binary)

    port_args = ["--port", str(port)]
    prefix    = _probe_invocation_prefix(binary)
    harness_args = prefix + concrete_args + port_args
    result = subprocess_harness(
        binary=binary,
        args=harness_args,
        port=port,
        setup_files={},
        http_sequence=[
            HTTPRequest(method=method, path=f"{route}?{param}=id>>{marker}")
        ],
        marker_path=marker,
    )
    return None if result.success else result.failure_reason


def _verify_config_file(
    state: SinkState,
    file_opts: List[ConfigurationOption],
    state_opts: List[ConfigurationOption],
    port: int,
    input_path: dict,
) -> Optional[str]:
    """
    Write config file, optionally fire init request, then fire exec request.
    Returns None on success, VerifyFailure value on failure.
    """
    binary = state["binary"]
    gate_conditions = state.get("gate_conditions", [])

    # Derive config file path from gate_conditions (set by classify_gate_source)
    config_path = None
    for cond in gate_conditions:
        if cond.get("config_path"):
            config_path = cond["config_path"]
            break
    if config_path is None:
        config_path = f"/tmp/{os.path.basename(binary)}_exec.conf"

    # Build config file content from file-type preconditions
    config_lines = []
    for opt in file_opts:
        value = opt.configuration_value or "1"
        config_lines.append(f"{opt.configuration_parameter}={value}")
    config_content = "\n".join(config_lines) + "\n"

    route  = input_path.get("route", "/exec")
    param  = input_path.get("param", "cmd")
    method = input_path.get("method", "GET").upper()
    marker = _build_marker(binary)

    # Build HTTP sequence
    http_seq = []
    for state_opt in state_opts:
        # Each runtime_state option is an init request
        token = state_opt.configuration_value or ""
        init_route = state_opt.configuration_parameter  # e.g. "/exec/init"
        http_seq.append(HTTPRequest(method="GET", path=f"{init_route}?token={token}"))

    http_seq.append(
        HTTPRequest(method=method, path=f"{route}?{param}=id>>{marker}")
    )

    port_args = ["--port", str(port)]
    prefix    = _probe_invocation_prefix(binary)
    harness_args = prefix + port_args
    result = subprocess_harness(
        binary=binary,
        args=harness_args,
        port=port,
        setup_files={config_path: config_content},
        http_sequence=http_seq,
        marker_path=marker,
    )
    return None if result.success else result.failure_reason


# ---------------------------------------------------------------------------
# Main node
# ---------------------------------------------------------------------------

def verify_node(state: SinkState) -> dict:
    hypothesis  = state.get("precondition_hypothesis", [])
    attempts    = state.get("verify_attempts", 0)
    port        = state["port"]
    sink        = state["sink"]
    input_path  = state.get("input_path") or {}

    flag_opts   = _present(hypothesis, ConfigurationType.flag)
    file_opts   = _present(hypothesis, ConfigurationType.file)
    state_opts  = _present(hypothesis, ConfigurationType.runtime_state)

    # Choose strategy based on what precondition types are present
    if state_opts or file_opts:
        failure = _verify_config_file(state, file_opts, state_opts, port, input_path)
    else:
        failure = _verify_cli_flags(state, flag_opts, sink.addr, port, input_path)

    new_attempts = attempts + 1

    if failure is None:
        # Success
        result = SinkResult(
            sink=sink,
            verdict=Verdict.Exploitable,
            preconditions=hypothesis,
            attempts=new_attempts,
            evidence={
                "gate_source":   state.get("gate_source"),
                "input_path":    input_path,
                "sanitization":  state.get("sanitization"),
            },
        )
        return {
            "verify_attempts":      new_attempts,
            "verify_failure_reason": None,
            "results": [result],
        }

    # Failure: record reason for synthesis revision or conclude Inconclusive
    return {
        "verify_attempts":       new_attempts,
        "verify_failure_reason": failure,
    }
