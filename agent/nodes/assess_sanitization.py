"""assess_sanitization node: find sanitization on the input path and determine
whether it is always-on, bypassable, or itself config-gated (S3 pattern).

S3 pattern: the sanitization check (e.g. strpbrk shell-metachar filter) is
wrapped in an if(some_flag) block.  That flag must be ABSENT for exploitation,
so it becomes an absent-sense precondition.
"""

from __future__ import annotations

from langchain_core.tools import tool

from nodes.common import extract_json_block, make_joern_raw_tool, run_analysis_agent
from state import SinkState
from tools import decompile_function, function_call_sequence, objdump, trace_condition


_SYSTEM = """\
You are a binary analysis agent assessing sanitization on the input path.

Look for:
  - Character-filter functions: strpbrk, strchr, strcspn checking for shell
    metacharacters (;|&$`\\ etc.)
  - Allowlist/blocklist comparisons
  - Any conditional that blocks or modifies the attacker-controlled string
    before it reaches the sink

Use asm_function first for local analysis (control flow, compare/branch patterns,
call ordering within a function). Use joern_* tools only for cross-function
concerns: finding all callers, tracing variables across function boundaries, or
dataflow that spans multiple functions.

For each sanitization found determine:
  1. Is it ALWAYS active (no bypass possible)? → exploitation blocked
  2. Is it BYPASSABLE (e.g. only filters pipe "|" but not ";")? → note the bypass
  3. Is it CONFIG-GATED (the sanitization runs only if some flag is set)?
     → that flag must be absent for exploitation; this becomes an absent-sense
       precondition (S3 pattern)

Use asm_function on the sink's containing function first to see all calls and
branches in assembly.  Use joern_trace_condition on the sanitization call site to
detect case 3 when the branch is not visible in a single function.

Return a JSON object:
{
  "sanitization_present": true | false,
  "always_active":        true | false,
  "bypassable":           true | false,
  "bypass_method":        "description or null",
  "config_gated":         true | false,
  "gate_variable":        "C variable controlling sanitation, or null",
  "gate_flag_or_key":     "CLI flag / config key that enables sanitization, or null",
  "gate_source":          "argv" | "config_file" | null
}

If sanitization_present is false, all other fields can be null/false.
"""


def assess_sanitization_node(state: SinkState) -> dict:
    cpg_path   = state["joern_cpg"]
    sink       = state["sink"]
    input_path = state.get("input_path") or {}
    binary     = state["binary"]

    @tool
    def asm_function(function_name: str) -> str:
        """Disassemble a named function. Use this first — fastest tool available.
        Shows compare/branch patterns, call ordering, and argument setup.
        Args:
            function_name: exact C function name.
        """
        return objdump(binary, function=function_name)

    @tool
    def joern_function_calls(function_name: str) -> str:
        """List all calls in a function sorted by address.

        Use this on the sink's containing function to see if any filter
        functions (strchr, strpbrk, etc.) appear between the input and the sink,
        and whether they are themselves guarded by compare/goto patterns.

        Args:
            function_name: exact function name.
        """
        return function_call_sequence(cpg_path, function_name)

    @tool
    def joern_trace_condition(addr: str) -> str:
        """Find dominating branch conditions for the node at address *addr*.

        Args:
            addr: hex address string.
        """
        return trace_condition(cpg_path, addr)

    @tool
    def joern_decompile(function_name: str) -> str:
        """Decompile a function to inspect sanitization logic.

        Args:
            function_name: exact C function name.
        """
        return decompile_function(cpg_path, function_name)

    joern_raw = make_joern_raw_tool(cpg_path)

    user_msg = (
        f"Sink: {sink.function}() at {hex(sink.addr)} in '{sink.caller}'.\n"
        f"Binary: {state['binary']}\n"
        f"Input path findings: {input_path}\n\n"
        "Check for sanitization functions (strpbrk, strchr, strcmp-based filters) "
        "between the HTTP input source and the sink.  Determine if any are config-gated."
    )

    try:
        response = run_analysis_agent(
            system_prompt=_SYSTEM,
            user_message=user_msg,
            tools=[
                asm_function,
                joern_function_calls,
                joern_trace_condition,
                joern_decompile,
                joern_raw,
            ],
            node_name="assess_sanitization",
        )
    except (RuntimeError, ValueError):
        return {"sanitization": {
            "sanitization_present": False,
            "always_active": False,
            "bypassable": True,
            "config_gated": False,
        }}

    try:
        data = extract_json_block(response)
    except ValueError:
        data = {
            "sanitization_present": False,
            "always_active": False,
            "bypassable": True,
            "config_gated": False,
        }

    return {"sanitization": data}
