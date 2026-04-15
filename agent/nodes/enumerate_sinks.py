"""enumerate_sinks node: find dangerous call sites in the CPG."""

from __future__ import annotations

import json
from typing import List

from langchain_core.tools import tool

from models import DANGEROUS_FUNCTIONS, Sink
from nodes.common import extract_json_block, make_joern_raw_tool, run_analysis_agent
from state import GraphState
from tools import find_call_sites


_SYSTEM = """\
You are a binary analysis agent.  Your task is to enumerate all call sites for
dangerous functions (system, execve, execvp, execvpe, execl, execle, execlp,
popen) in the binary's Code Property Graph.

Use the available tools to find every call site.  The tool returns lines in the
format:  CALL|<function>|<caller>|<addr_decimal>

Then return a JSON array of sink objects.  Each object must have:
  addr      – the address as a hex string (convert addr_decimal: hex(int(addr_decimal)))
  function  – name of the dangerous function called ("system", "execve", etc.)
  arg_index – integer index of the argument that carries attacker data (usually 0)
  caller    – name of the C function that contains this call site

Return ONLY the JSON array, no prose.  Example:
[{"addr":"0x401234","function":"system","arg_index":0,"caller":"handle_exec"}]

If no dangerous call sites are found, return an empty array: []
"""


def enumerate_sinks_node(state: GraphState) -> dict:
    cpg_path = state["joern_cpg"]

    @tool
    def joern_find_dangerous_calls(function_name: str) -> str:
        """Find call sites for a named dangerous function in the CPG.

        Args:
            function_name: one of system, execve, execvp, popen, etc.
        """
        return find_call_sites(cpg_path, [function_name])

    joern_raw = make_joern_raw_tool(cpg_path)

    user_msg = (
        f"Binary: {state['binary']}\n"
        f"Find all call sites for: {', '.join(sorted(DANGEROUS_FUNCTIONS))}"
    )

    try:
        response = run_analysis_agent(
            system_prompt=_SYSTEM,
            user_message=user_msg,
            tools=[joern_find_dangerous_calls, joern_raw],
            node_name="enumerate_sinks",
        )
        raw = extract_json_block(response)
    except (RuntimeError, ValueError) as exc:
        # Max iterations or malformed JSON — treat as no sinks found rather
        # than crashing the whole analysis.
        import logging
        logging.getLogger("agent").warning(
            "enumerate_sinks: returning empty list after error: %s", exc
        )
        raw = []

    sinks: List[Sink] = []
    for entry in raw:
        try:
            addr_val = entry.get("addr", "0")
            sinks.append(Sink(
                addr=int(addr_val, 16) if isinstance(addr_val, str) else int(addr_val),
                function=entry.get("function", "system"),
                arg_index=int(entry.get("arg_index", 0)),
                caller=entry.get("caller", "unknown"),
            ))
        except (ValueError, TypeError):
            continue

    return {"sink_list": sinks}
