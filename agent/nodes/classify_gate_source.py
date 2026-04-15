"""classify_gate_source node: determine the mechanism that populates each guard variable.

Output: gate_source ∈ {"cli_flag", "config_file", "runtime_http_sequence"}
and enriched gate_conditions with enough detail to construct a concrete harness.

Note: no corpus-specific taxonomy labels (C1/C2/C3) appear here.  Those are
derived by the scoring layer from the precondition types the agent produces.
"""

from __future__ import annotations

from langchain_core.tools import tool

from nodes.common import extract_json_block, make_joern_raw_tool, run_analysis_agent
from state import SinkState
from tools import decompile_function, get_callers, get_variable_defs, objdump, strings


_SYSTEM = """\
You are a binary analysis agent classifying how a gate variable is populated.

Gate source mechanisms:
  cli_flag              – the variable is set by parsing argv (command-line flags).
                          The flag name(s) and whether a value is required matter.
  config_file           – the variable is set by reading a config file at runtime
                          (fopen / fgets / sscanf / getline / getenv pointing at a
                          file path).  The file path, key name, and expected value matter.
  runtime_http_sequence – the variable is set by a separate HTTP request to an
                          initialisation endpoint BEFORE the main exploit request.
                          There may also be a config file involved.  The init route,
                          any required token/secret, and the order of requests matter.

Use asm_function first for local analysis (control flow, compare/branch patterns,
call ordering within a function). Use joern_* tools only for cross-function
concerns: finding all callers, tracing variables across function boundaries, or
dataflow that spans multiple functions.

For each gate condition provided, trace where the variable is assigned:
  - argv / getopt / optarg / argc    → cli_flag
  - fopen / fgets / sscanf / fgetc   → config_file
  - a global flag set inside an HTTP request handler for a different route
                                     → runtime_http_sequence

Return a JSON object:
{
  "gate_source": "cli_flag" | "config_file" | "runtime_http_sequence",
  "conditions": [
    {
      "variable":       "C variable name",
      "source_fn":      "function where the variable is assigned (e.g. parse_args, load_config)",
      "flag_or_key":    "CLI flag name (e.g. --exec-mode) or config key (e.g. exec_mode)",
      "expected_value": "value that enables the gate, or null for flag presence",
      "config_path":    "hardcoded config file path, or null",
      "init_route":     "HTTP path for initialisation endpoint, or null",
      "init_token":     "token/secret value for the init endpoint, or null"
    }
  ]
}

Extract the exact names and values as they appear in the binary — do not guess
or normalise yet.  The precondition synthesis step will canonicalise them.
"""


def classify_gate_source_node(state: SinkState) -> dict:
    cpg_path   = state["joern_cpg"]
    binary     = state["binary"]
    conditions = state.get("gate_conditions", [])

    @tool
    def asm_function(function_name: str) -> str:
        """Disassemble a named function. Use this first — fastest tool available.
        Shows compare/branch patterns, call ordering, and argument setup.
        Args:
            function_name: exact C function name.
        """
        return objdump(binary, function=function_name)

    @tool
    def joern_variable_defs(variable_name: str) -> str:
        """Find all assignments to a variable, revealing where it is populated.

        Args:
            variable_name: C identifier.
        """
        return get_variable_defs(cpg_path, variable_name)

    @tool
    def joern_decompile(function_name: str) -> str:
        """Decompile a function to inspect argument parsing or config-file reading.

        Args:
            function_name: exact C function name.
        """
        return decompile_function(cpg_path, function_name)

    @tool
    def joern_get_callers(function_name: str) -> str:
        """List all callers of a function.

        Args:
            function_name: C function name.
        """
        return get_callers(cpg_path, function_name)

    @tool
    def binary_strings(min_length: int = 4) -> str:
        """Extract printable strings from the binary.

        Useful for finding config-file paths, CLI flag strings, HTTP route
        strings, and hardcoded tokens/secrets.

        Args:
            min_length: minimum string length to include (default 4).
        """
        return "\n".join(strings(binary, min_length=min_length))

    joern_raw = make_joern_raw_tool(cpg_path)

    user_msg = (
        f"Binary: {binary}\n"
        f"Gate conditions to classify:\n{conditions}\n\n"
        "For each variable in the gate conditions, trace where it is assigned "
        "to determine whether the gate is set via CLI arguments, a config file, "
        "or a runtime HTTP request sequence.  "
        "Extract exact flag names, config keys, expected values, file paths, "
        "init routes, and tokens."
    )

    response = run_analysis_agent(
        system_prompt=_SYSTEM,
        user_message=user_msg,
        tools=[
            asm_function,
            joern_variable_defs,
            joern_decompile,
            joern_get_callers,
            binary_strings,
            joern_raw,
        ],
        node_name="classify_gate_source",
    )

    try:
        data = extract_json_block(response)
    except ValueError:
        data = {"gate_source": "cli_flag", "conditions": conditions}

    return {
        "gate_source":     data.get("gate_source", "cli_flag"),
        "gate_conditions": data.get("conditions", conditions),
    }
