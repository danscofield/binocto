"""trace_gate node: backward slice from sink to find guard conditions."""

from __future__ import annotations

from langchain_core.tools import tool

from nodes.common import extract_json_block, make_joern_raw_tool, run_analysis_agent
from state import SinkState
from tools import (
    decompile_function,
    function_call_sequence,
    get_variable_defs,
    objdump,
    trace_condition,
)


_SYSTEM = """\
You are a binary analysis agent performing backward gate analysis.

Your goal: find the conditional guards (if-statements, boolean checks) that
control whether the dangerous sink function is actually executed.  These guards
represent the "gate" — the configuration or runtime state that must be true for
exploitation to be possible.

Use asm_function first for local analysis (control flow, compare/branch patterns,
call ordering within a function). Use joern_* tools only for cross-function
concerns: finding all callers, tracing variables across function boundaries, or
dataflow that spans multiple functions.

Use the available tools to:
1. Disassemble the sink's containing function with asm_function to read control
   flow, compare/branch patterns, and the call ordering directly from the binary.
2. Use joern_trace_condition to find dominating conditions for the sink's address.
3. Use joern_decompile for higher-level control-flow confirmation when needed.
4. Use joern_variable_defs (cross-function) to trace where guard variables are set.

Return a JSON object:
{
  "conditions": [
    {
      "variable":   "name of the C variable checked in the guard",
      "check":      "e.g. variable != 0, variable == 1, strcmp(s, ...) == 0",
      "set_in":     "function where this variable is assigned",
      "line":       42
    }
  ],
  "sink_containing_fn": "name of the function that directly calls the sink"
}

List every guard condition between the HTTP request handler and the sink call.
"""


def trace_gate_node(state: SinkState) -> dict:
    cpg_path = state["joern_cpg"]
    sink     = state["sink"]
    binary   = state["binary"]

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
        """List all calls in a function sorted by address (assembly-level view).

        Shows compare/goto patterns and what functions are called and in what order.
        Use this on the sink's containing function and its callers to find guards.

        Args:
            function_name: exact C/binary function name.
        """
        return function_call_sequence(cpg_path, function_name)

    @tool
    def joern_trace_condition(addr: str) -> str:
        """Find dominating branch conditions for the node at address *addr*.

        Args:
            addr: hex address string, e.g. "0x401234".
        """
        return trace_condition(cpg_path, addr)

    @tool
    def joern_decompile(function_name: str) -> str:
        """Decompile a function to inspect its control flow.

        Args:
            function_name: exact C function name.
        """
        return decompile_function(cpg_path, function_name)

    @tool
    def joern_variable_defs(variable_name: str) -> str:
        """Find all definitions and uses of a variable.

        Args:
            variable_name: C identifier name.
        """
        return get_variable_defs(cpg_path, variable_name)

    joern_raw = make_joern_raw_tool(cpg_path)

    user_msg = (
        f"Sink: {sink.function}() at {hex(sink.addr)} in '{sink.caller}'.\n"
        f"Binary: {state['binary']}\n\n"
        "Trace backward from the sink to identify every guard condition that "
        "must be satisfied for the sink to execute."
    )

    response = run_analysis_agent(
        system_prompt=_SYSTEM,
        user_message=user_msg,
        tools=[
            asm_function,
            joern_function_calls,
            joern_trace_condition,
            joern_decompile,
            joern_variable_defs,
            joern_raw,
        ],
        node_name="trace_gate",
    )

    try:
        data = extract_json_block(response)
    except ValueError:
        data = {"conditions": [], "sink_containing_fn": sink.caller}

    conditions = data.get("conditions", [])
    return {"gate_conditions": conditions}
