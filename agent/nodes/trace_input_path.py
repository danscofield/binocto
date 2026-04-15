"""trace_input_path node: confirm HTTP input → sink taint path and extract route."""

from __future__ import annotations

from langchain_core.tools import tool

from nodes.common import extract_json_block, make_joern_raw_tool, run_analysis_agent
from state import SinkState
from tools import decompile_function, forward_taint, get_callers, objdump


_SYSTEM = """\
You are a binary analysis agent tracing the attacker-controlled input path.

Your goal: confirm that externally-supplied request data flows to the dangerous
sink, and extract:
  1. The entry point / route that triggers the vulnerability (e.g. /exec).
  2. The query parameter or request body field that carries the payload
     (e.g. "cmd").
  3. How many function call boundaries the input crosses before reaching the sink.
  4. Whether there is any intermediate transformation (snprintf into a buffer,
     struct field assignment, etc.).

Use asm_function first for local analysis (control flow, compare/branch patterns,
call ordering within a function). Use joern_* tools only for cross-function
concerns: finding all callers, tracing variables across function boundaries, or
dataflow that spans multiple functions.

Use asm_function on the handler and sink-caller functions to read argument setup
and string comparisons directly from the binary. Use forward taint analysis from
input source functions when the path spans multiple functions.

hop_count is the number of C function call boundaries the input crosses between
the point where it is received from the external caller and the point where it
is passed to the dangerous sink.  Count only non-trivial boundaries (not wrappers
that immediately return):
  1 = the receiving function directly calls the sink
  2 = one intermediate function between receiver and sink
  3 = two or more intermediate functions

Return a JSON object:
{
  "entry_point":     "/exec",
  "method":          "GET" | "POST" | "ANY",
  "param":           "cmd",
  "delivery":        "direct" | "snprintf_buffer" | "struct_field",
  "handler_fn":      "name of the C function handling the entry point",
  "hop_count":       1,
  "taint_confirmed": true | false
}
"""

_HTTP_SOURCES = [
    "recv", "read", "fread", "getenv", "sscanf", "strstr", "strtok",
    "mg_http_get_var", "mg_query_var", "http_request_get_query_string",
    "evhttp_request_get_uri", "onion_request_get_query",
]


def trace_input_path_node(state: SinkState) -> dict:
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
        """Forward taint from an HTTP source function to the sink.

        Args:
            source_fn: name of a source function (e.g. "recv", "mg_http_get_var").
        """
        return forward_taint(cpg_path, [source_fn], sink.function)

    @tool
    def joern_decompile(function_name: str) -> str:
        """Decompile a function.

        Args:
            function_name: exact C function name.
        """
        return decompile_function(cpg_path, function_name)

    @tool
    def joern_get_callers(function_name: str) -> str:
        """List callers of a function.

        Args:
            function_name: C function name.
        """
        return get_callers(cpg_path, function_name)

    joern_raw = make_joern_raw_tool(cpg_path)

    user_msg = (
        f"Sink: {sink.function}() at {hex(sink.addr)} in '{sink.caller}'.\n"
        f"Binary: {state['binary']}\n"
        f"Common HTTP source functions: {', '.join(_HTTP_SOURCES)}\n\n"
        "Trace the input path from HTTP request to sink.  Identify the route, "
        "parameter name, and delivery mechanism."
    )

    try:
        response = run_analysis_agent(
            system_prompt=_SYSTEM,
            user_message=user_msg,
            tools=[asm_function, joern_forward_taint, joern_decompile, joern_get_callers, joern_raw],
            node_name="trace_input_path",
        )
    except (RuntimeError, ValueError):
        return {"input_path": {
            "entry_point": "unknown", "param": "unknown",
            "delivery": "direct", "handler_fn": sink.caller,
            "hop_count": 1, "taint_confirmed": False,
        }}

    try:
        data = extract_json_block(response)
    except ValueError:
        data = {
            "entry_point": "unknown", "param": "unknown",
            "delivery": "direct", "handler_fn": sink.caller,
            "hop_count": 1, "taint_confirmed": False,
        }

    return {"input_path": data}
