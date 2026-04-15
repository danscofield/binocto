"""trace_and_classify_gate node: find gate conditions AND classify their source in one pass.

Replaces the separate trace_gate_node + classify_gate_source_node with a single
LLM agent pass that answers both questions simultaneously, saving one full
agentic loop and reducing total tool calls.

Output: sets both ``gate_conditions`` and ``gate_source`` in state.
"""

from __future__ import annotations

from langchain_core.tools import tool

from nodes.common import extract_json_block, make_joern_raw_tool, run_analysis_agent
from state import SinkState
from tools import get_callers, get_variable_defs, objdump, strings, trace_condition


_SYSTEM = """\
You are a binary analysis agent performing gate analysis in one pass: find the
conditions that guard the dangerous sink AND determine how those conditions are set.

STEP 1 — Identify ALL gate conditions (including in caller functions):
  Start with asm_function on the sink's containing function to read its assembly.
  A gate condition is a compare/test instruction before the sink call; the branch
  result determines whether execution reaches the sink.

  EXHAUSTIVE ENUMERATION: binaries often have MULTIPLE independent gate checks —
  e.g. three separate flag variables that must all be non-zero. Walk every cmp/test
  instruction on the path from function entry to the sink call. Do not stop at the
  first gate. List every variable that is independently tested.

  CALLER FUNCTIONS: Gate conditions are often checked in the function that CALLS
  the sink's containing function, not in the sink function itself.  A dispatcher
  or router may check flags before delegating to the handler.  Always:
    1. Read the sink's containing function (asm_function on sink.caller).
    2. Call joern_get_callers on sink.caller to find its callers.
    3. Read each caller function with asm_function to find any cmp/test before
       the call to sink.caller — those are also gate conditions you must include.
    4. Repeat one further level up if the evidence suggests another gate there.
  Missing an upstream gate produces an INCOMPLETE precondition set that will
  fail verification, so be thorough.

  For each guard variable, use joern_get_variable_defs to find where it is assigned.
  Use joern_trace_condition on the sink address to see the dominating call context.

STEP 2 — Classify each variable's source mechanism:
  cli_flag          → variable is assigned in a function that iterates argv,
                      calls getopt, or compares strings starting with "-"
  config_file       → variable is assigned in a function that calls fopen/fgets/
                      sscanf/getline on a file path
  runtime_sequence  → variable is set by a prior external request or operation;
                      e.g. an HTTP init endpoint, a protocol handshake, a
                      preceding command that must be issued before the sink path

  Use binary_strings to find exact flag names, config key names, file paths,
  init routes, and tokens as they appear in the binary.
  Use joern_get_callers to trace call chains when the assignment is not visible
  in the immediate function.

VERIFIED FLAG NAMES — mandatory rule:
  Before reporting any CLI flag or config key in your JSON answer, you MUST confirm
  that its exact string appears in binary_strings output.  Call binary_strings early
  and search its output for every flag name you intend to report.

  Do NOT guess or infer flag names from context (e.g. do not assume "--exec-logging"
  exists because "--exec-mode" exists).  Do NOT report a flag unless you have seen
  its literal string (e.g. "--exec-logging") in the binary.  If a gate variable's
  source flag cannot be confirmed in strings, set flag_or_key to null rather than
  guessing.

Tool strategy:
  asm_function            ALWAYS first — fast, no JVM overhead
  binary_strings          call early to enumerate ALL flag/key strings in the binary;
                          use this output to verify every flag name you report
  joern_get_variable_defs cross-function variable assignment tracing
  joern_trace_condition   dominating conditions at a specific address
  joern_get_callers       call chains
  joern_raw               last resort only — stop if a query returns errors twice

STOP CONDITION: Once you can identify the gate variable(s) and their source, stop
calling tools and return the JSON answer. Do not keep probing if the evidence is clear.
If tools return empty results or errors repeatedly, produce your best-effort answer
based on what you have already found.

Return a JSON object:
{
  "gate_source": "cli_flag" | "config_file" | "runtime_sequence",
  "conditions": [
    {
      "variable":       "C variable name or global at address",
      "source_fn":      "function where assigned",
      "flag_or_key":    "CLI flag (e.g. --exec-mode) or config key (e.g. exec_mode)",
      "expected_value": "value enabling the gate, or null for flag presence",
      "config_path":    "config file path, or null",
      "init_route":     "route/operation for runtime_sequence, or null",
      "init_token":     "token/secret, or null"
    }
  ]
}
"""


def trace_and_classify_gate_node(state: SinkState) -> dict:
    """Run a single agentic pass that identifies gate conditions and classifies
    the source mechanism (cli_flag, config_file, runtime_sequence).

    Returns a dict with keys ``gate_source`` and ``gate_conditions``.
    """
    cpg_path = state["joern_cpg"]
    binary   = state["binary"]
    sink     = state["sink"]

    @tool
    def asm_function(function_name: str) -> str:
        """Disassemble a named function. Use this first — fastest tool available.
        Shows compare/branch patterns, call ordering, and argument setup.
        Args:
            function_name: exact C function name.
        """
        return objdump(binary, function=function_name)

    @tool
    def joern_get_variable_defs(variable_name: str) -> str:
        """Find all assignments to a variable across the whole binary (cross-function).
        Use for tracing where a gate variable is written by config parsing.
        Args:
            variable_name: C identifier or config key string.
        """
        return get_variable_defs(cpg_path, variable_name)

    @tool
    def joern_trace_condition(addr: str) -> str:
        """Find dominating branch conditions for the node at address *addr*.
        Shows the containing function's call sequence and those of its callers.
        Args:
            addr: hex address string, e.g. "0x401234".
        """
        return trace_condition(cpg_path, addr)

    @tool
    def joern_get_callers(function_name: str) -> str:
        """List all functions that call function_name (cross-function call graph).
        Args:
            function_name: C function name.
        """
        return get_callers(cpg_path, function_name)

    @tool
    def binary_strings(min_length: int = 4) -> str:
        """Extract printable strings from the binary.
        Use to find exact flag names, config key names, file paths, init routes,
        and tokens as they appear in the binary.
        Args:
            min_length: minimum string length (default 4).
        """
        return "\n".join(strings(binary, min_length=min_length))

    joern_raw = make_joern_raw_tool(cpg_path)

    user_msg = (
        f"Binary: {binary}\n"
        f"Sink: {sink.function}() at {hex(sink.addr)} in '{sink.caller}'.\n\n"
        "Perform gate analysis in one pass:\n"
        "  STEP 1: Identify every guard condition that controls whether the sink executes.\n"
        "    - Read the sink's containing function.\n"
        "    - Then call joern_get_callers on that function and read each caller to find\n"
        "      any upstream gate checks in dispatcher/router functions.\n"
        "  STEP 2: Classify the source mechanism for each guard variable "
        "(cli_flag, config_file, or runtime_sequence).\n\n"
        f"Start with asm_function on '{sink.caller}' to read the assembly around the sink.\n"
        f"Then use joern_get_callers('{sink.caller}') to find its callers and check them too."
    )

    try:
        response = run_analysis_agent(
            system_prompt=_SYSTEM,
            user_message=user_msg,
            tools=[
                asm_function,
                joern_get_variable_defs,
                joern_trace_condition,
                joern_get_callers,
                binary_strings,
                joern_raw,
            ],
            node_name="trace_and_classify_gate",
        )
    except (RuntimeError, ValueError) as exc:
        import logging
        logging.getLogger("agent").warning(
            "trace_and_classify_gate: returning default after error: %s", exc
        )
        return {"gate_source": "cli_flag", "gate_conditions": []}

    try:
        data = extract_json_block(response)
    except ValueError:
        data = {"gate_source": "cli_flag", "conditions": []}

    return {
        "gate_source":     data.get("gate_source", "cli_flag"),
        "gate_conditions": data.get("conditions", []),
    }
