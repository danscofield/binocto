"""check_input_reach node: fast-fail if no attacker-controlled data reaches sink.

High recall > precision: only mark NotReachable when confident.
"""

from __future__ import annotations

from langchain_core.tools import tool

from nodes.common import extract_json_block, make_joern_raw_tool, run_analysis_agent
from state import SinkState
from tools import decompile_function, forward_taint, get_callers, objdump, strings


_SYSTEM = """\
You are a binary analysis agent performing a fast-fail reachability check.

Your goal: determine whether attacker-controlled data (arriving via HTTP request
parsing — typically from functions like recv, read, getenv, query-string parsing,
or similar I/O entry points) can flow to the sink function's argument.

Use asm_function first for local analysis (control flow, compare/branch patterns,
call ordering within a function). Use joern_* tools only for cross-function
concerns: finding all callers, tracing variables across function boundaries, or
dataflow that spans multiple functions.

Use the available tools to:
1. Disassemble the sink's caller with asm_function to inspect argument setup and
   call ordering directly in the binary.
2. Run a forward taint analysis from known HTTP-input source functions if local
   assembly is inconclusive.
3. If taint analysis is inconclusive, decompile the caller and inspect manually.
4. Look at the call graph: which functions call the sink's caller?

Return a JSON object:
{
  "reachable": true | false,
  "confidence": "high" | "medium" | "low",
  "reason": "one-sentence explanation"
}

Default to reachable=true when uncertain (high recall).
Return reachable=false only when you have high-confidence evidence that no
HTTP-sourced data can ever reach the sink (e.g. the argument is always a
compile-time constant).
"""

# Common HTTP-layer source function names across the server libraries in corpus
_HTTP_SOURCES = [
    "recv", "read", "fread", "getenv", "sscanf", "strstr",
    "strtok", "mg_http_get_var", "mg_query_var",
    "http_request_get_query_string", "evhttp_request_get_uri",
    "onion_request_get_query",
]


def check_input_reach_node(state: SinkState) -> dict:
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
    def joern_forward_taint(source_fn: str) -> str:
        """Forward taint from *source_fn* to the sink.  source_fn is a C function name.

        Args:
            source_fn: name of a source function (e.g. "recv", "getenv").
        """
        return forward_taint(cpg_path, [source_fn], sink.function)

    @tool
    def joern_decompile(function_name: str) -> str:
        """Decompile a C function to inspect data flow manually.

        Args:
            function_name: exact C function name to decompile.
        """
        return decompile_function(cpg_path, function_name)

    @tool
    def joern_get_callers(function_name: str) -> str:
        """List all functions that call *function_name*.

        Args:
            function_name: C function name.
        """
        return get_callers(cpg_path, function_name)

    joern_raw = make_joern_raw_tool(cpg_path)

    user_msg = (
        f"Sink: {sink.function}() at address {hex(sink.addr)} "
        f"(argument index {sink.arg_index}), in function '{sink.caller}'.\n"
        f"Binary: {state['binary']}\n\n"
        f"Common HTTP source functions to try: {', '.join(_HTTP_SOURCES)}\n"
        "Determine whether attacker-controlled HTTP input can reach the sink argument."
    )

    try:
        response = run_analysis_agent(
            system_prompt=_SYSTEM,
            user_message=user_msg,
            tools=[asm_function, joern_forward_taint, joern_decompile, joern_get_callers, joern_raw],
            node_name="check_input_reach",
        )
    except (RuntimeError, ValueError):
        return {"input_reachable": True}   # default to reachable (high recall)

    try:
        data = extract_json_block(response)
        reachable = bool(data.get("reachable", True))
    except ValueError:
        reachable = True   # default to reachable on parse failure

    return {"input_reachable": reachable}
