"""setup node: build Joern CPG, collect binary metadata."""

from __future__ import annotations

from state import GraphState
from tools import binary_info, build_cpg, start_joern_server, strings


def setup_node(state: GraphState) -> dict:
    """Build the Joern CPG for the binary and stash metadata in state.

    This node runs exactly once per analysis run.  It is intentionally
    not LLM-powered; it performs deterministic setup steps.
    """
    binary = state["binary"]

    # Build CPG (slow; ~30-120 s depending on binary size)
    cpg_path = build_cpg(binary)

    # Start a persistent Joern HTTP server so subsequent queries avoid the
    # per-query JVM startup overhead (~10 s each).
    start_joern_server(cpg_path)

    return {
        "joern_cpg": cpg_path,
        "results": [],   # initialise accumulator
    }
