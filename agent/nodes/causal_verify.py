"""causal_verify node: confirm the exploit hypothesis by tracing the causal chain
through the binary's assembly and code property graph — no binary execution.

Four causal links must all hold for verdict=Exploitable:

  1. config_to_variable  — the configuration option (CLI flag / config key /
                           HTTP init route) actually writes the gate variable.
  2. variable_to_gate    — that variable is tested in the branch guarding the sink.
  3. gate_to_sink        — when the branch is satisfied, execution reaches the sink.
  4. input_to_argument   — the HTTP-supplied payload is the argument to the sink.

Tool selection:
  asm_function            → ALWAYS try first. Fast (no JVM). Correct for links 2, 3,
                            and often 4. Read the gate function and the handler function.
  joern_get_variable_defs → link 1: where is the variable assigned across functions?
  joern_forward_taint     → link 4: when handler and sink are in different functions
  joern_get_callers       → finding call chains not visible in a single function
  binary_strings          → confirming exact flag/key/route strings exist in the binary

Architecture-independent: works on any ISA objdump supports.
"""

from __future__ import annotations

import json
from typing import List

from langchain_core.tools import tool

from models import CausalFailure, ConfigurationOption, SinkResult, Verdict
from nodes.common import extract_json_block, make_joern_raw_tool, run_analysis_agent
from state import MAX_VERIFY_ATTEMPTS, SinkState
from tools import (
    angr_find_path,
    forward_taint,
    get_callers,
    get_variable_defs,
    objdump,
    strings,
)


_SYSTEM = """\
You are a binary analysis agent performing static causal verification of an exploit hypothesis.

You must confirm four causal links that together prove a command injection vulnerability:

  1. config_to_variable — the configuration option (CLI flag / config-file key / HTTP init
     request) actually writes the gate variable into program memory.
     ► Read the config-parsing function in assembly. Confirm the exact option string and the
       instruction that stores it into the variable.

  2. variable_to_gate — the stored variable is the one tested in the branch guarding the sink.
     ► Read the gate/sink function in assembly. Find the cmp/test instruction and confirm it
       loads from the same location the config parser wrote to.

  3. gate_to_sink — when the branch condition is satisfied, execution reaches the sink with
     no additional blocking condition.
     ► In the same function, trace the fall-through or taken-jump from the branch to the call.

  4. input_to_argument — the HTTP-supplied payload is the (untransformed or only trivially
     wrapped) first argument to the sink function.
     ► Forward taint from HTTP input functions, or read the handler function in assembly.

Tool selection guidance:
  asm_function          ALWAYS try first. No JVM overhead. Sufficient for links 2, 3,
                        and often 4. One call per function; read carefully before reaching
                        for Joern.
  joern_get_variable_defs  Use for link 1 when the variable is set in a different function
                        from the gate — Joern finds cross-function assignments.
  joern_forward_taint   Use for link 4 when handler and sink are far apart in the call graph.
  joern_get_callers     Use to find the chain from HTTP handler down to the gate function.
  binary_strings        Confirm the exact flag/key/route strings literally exist in the binary.
  angr_solve_value      Use only when a comparison value is non-obvious from assembly
                        (magic integers, computed checks). Do not use for plain
                        strcmp()-against-literal comparisons.
  joern_raw             Last resort for bespoke CPG queries.

For runtime_state (C3) hypotheses — token verification:
  When the hypothesis includes a runtime_state precondition with a configuration_value
  (the secret token), you MUST confirm the exact token string:
  1. Use binary_strings to find string literals near the init handler.
  2. Confirm the predicted token appears verbatim in the binary.
  3. If the predicted token is absent from binary_strings output, the token is wrong.
     Return Inconclusive with broken_link=config_to_variable so synthesis can find
     the correct value — do NOT return NotExploitable just because the token is wrong.

Return a JSON object:
{
  "verdict": "Exploitable" | "NotExploitable" | "Inconclusive",
  "confirmed_links": ["config_to_variable", "variable_to_gate", ...],
  "broken_link": null | "config_to_variable" | "variable_to_gate" | "gate_to_sink" | "input_to_argument",
  "broken_reason": "what specifically is wrong, or null if all confirmed",
  "evidence": "one paragraph: key assembly offsets / CPG facts that support the verdict"
}

Verdict rules:
  "Exploitable"     — all four links confirmed by assembly/CPG evidence.

  "NotExploitable"  — a causal link is STRUCTURALLY refuted: the binary's code makes
                      exploitation impossible regardless of configuration. Examples:
                        • the sink argument is always a hard-coded constant
                        • all paths to the sink sanitize the input unconditionally
                        • the sink is dead code / never reached from any handler
                      NOT for wrong hypothesis values — use Inconclusive for those.

  "Inconclusive"    — the hypothesis is incorrect (wrong flag names, wrong token, wrong
                      route) OR you cannot confirm/refute with available evidence.
                      Use Inconclusive whenever the binary might still be exploitable
                      with revised preconditions. The retry loop will correct the
                      hypothesis; prefer Inconclusive over NotExploitable when uncertain.
"""


def causal_verify_node(state: SinkState) -> dict:
    binary        = state["binary"]
    cpg_path      = state["joern_cpg"]
    sink          = state["sink"]
    hypothesis    = state.get("precondition_hypothesis", [])
    causal_chain  = state.get("causal_chain") or {}
    input_path    = state.get("input_path") or {}
    sanitization  = state.get("sanitization") or {}
    attempts      = state.get("verify_attempts", 0)

    # Build tools
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
    def joern_forward_taint(source_fn: str) -> str:
        """Forward taint from an HTTP source function to the sink.
        Use only when asm_function doesn't show the full input path.
        Args:
            source_fn: name of an HTTP input source function (e.g. "recv", "mg_http_get_var").
        """
        return forward_taint(cpg_path, [source_fn], sink.function)

    @tool
    def joern_get_callers(function_name: str) -> str:
        """List all functions that call function_name (cross-function call graph).
        Args:
            function_name: C function name.
        """
        return get_callers(cpg_path, function_name)

    joern_raw = make_joern_raw_tool(cpg_path)

    @tool
    def binary_strings(min_length: int = 4) -> str:
        """Extract printable strings from the binary.
        Use to confirm exact flag/key/route strings exist.
        Args:
            min_length: minimum string length (default 4).
        """
        return "\n".join(strings(binary, min_length=min_length))

    @tool
    def angr_solve_value(config_fn: str, gate_addr: str, flag_args: str) -> str:
        """Use symbolic execution to find the exact config option value that causes
        execution to reach the gate address (satisfying a non-obvious comparison).

        Use ONLY when assembly shows a comparison against a computed value, magic
        number, or integer constant that cannot be read as a plain string literal.
        Do NOT use for simple strcmp()-against-literal checks — read those from asm.

        Args:
            config_fn:  name of the function that parses the config option
                        (e.g. "parse_commandline", "load_config")
            gate_addr:  hex address of the branch/compare instruction at the gate
                        (e.g. "0x401234") — symbolic execution will try to reach
                        the instruction AFTER this address (the taken branch)
            flag_args:  space-separated argv to pass before the symbolic slot,
                        e.g. "--exec-value SYM" where SYM is the symbolic placeholder
        """
        find_addr = int(gate_addr, 16) + 4  # instruction after the compare
        sym_args  = flag_args.split()
        result = angr_find_path(
            binary=binary,
            find_addrs=[find_addr],
            symbolic_args=sym_args,
            timeout=90,
        )
        if result.sat:
            return f"SAT: satisfying input found: {result.input_values}"
        return f"UNSAT: no satisfying input found (timeout or genuinely unreachable)"

    hypothesis_json = json.dumps([o.model_dump() for o in hypothesis], indent=2)

    user_msg = (
        f"Binary: {binary}\n"
        f"Sink: {sink.function}() at {hex(sink.addr)} in '{sink.caller}'.\n\n"
        f"Hypothesis (preconditions to verify):\n{hypothesis_json}\n\n"
        f"Causal chain from synthesis:\n{json.dumps(causal_chain, indent=2)}\n\n"
        "Confirm or refute each causal link. Start with asm_function on the "
        f"gate/sink function '{sink.caller}' and the config-parsing function "
        "identified in the causal chain."
    )

    try:
        response = run_analysis_agent(
            system_prompt=_SYSTEM,
            user_message=user_msg,
            tools=[
                asm_function,
                joern_get_variable_defs,
                joern_forward_taint,
                joern_get_callers,
                joern_raw,
                binary_strings,
                angr_solve_value,
            ],
            node_name="causal_verify",
        )
    except (RuntimeError, ValueError):
        data = {"verdict": "Inconclusive", "broken_link": CausalFailure.INCONCLUSIVE}
    else:
        try:
            data = extract_json_block(response)
        except ValueError:
            data = {"verdict": "Inconclusive", "broken_link": CausalFailure.INCONCLUSIVE}

    verdict_str = data.get("verdict", "Inconclusive")
    broken_link = data.get("broken_link")
    broken_reason = data.get("broken_reason")
    evidence = data.get("evidence", "")

    new_attempts = attempts + 1

    if verdict_str == "Exploitable":
        result = SinkResult(
            sink=sink,
            verdict=Verdict.Exploitable,
            preconditions=hypothesis,
            attempts=new_attempts,
            evidence={
                "causal_chain":    causal_chain,
                "causal_evidence": evidence,
                "confirmed_links": data.get("confirmed_links", []),
                "input_path":      input_path,
                "sanitization":    sanitization,
            },
        )
        return {
            "verify_attempts":       new_attempts,
            "verify_failure_reason": None,
            "results":               [result],
        }

    if verdict_str == "NotExploitable":
        # Definitive negative — write terminal result and clear failure_reason
        # so route_after_causal_verify treats this as a terminal case (no retry).
        result = SinkResult(
            sink=sink,
            verdict=Verdict.NotExploitable,
            preconditions=hypothesis,
            attempts=new_attempts,
            evidence={
                "broken_link":   broken_link,
                "broken_reason": broken_reason,
                "evidence":      evidence,
                "input_path":    input_path,
                "sanitization":  sanitization,
            },
        )
        return {
            "verify_attempts":       new_attempts,
            "verify_failure_reason": None,
            "results":               [result],
        }

    # Inconclusive — record failure reason so synthesis can revise the hypothesis
    failure = broken_link or CausalFailure.INCONCLUSIVE
    return {
        "verify_attempts":       new_attempts,
        "verify_failure_reason": failure,
    }
