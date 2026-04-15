"""aggregate_results node: collapse per-sink results into a binary-level verdict.

Verdict rules:
  - Any Exploitable sink      → binary verdict Exploitable
    (use the sink with fewest preconditions as the canonical result)
  - All NotExploitable        → NotExploitable
  - Any Inconclusive + rest NotExploitable → Inconclusive
"""

from __future__ import annotations

from typing import List

from models import AnalysisResult, ConfigurationOption, SinkResult, Verdict
from state import GraphState
from tools import stop_joern_server


def aggregate_results_node(state: GraphState) -> dict:
    results: List[SinkResult] = state.get("results", [])
    binary  = state["binary"]

    # Shut down the persistent Joern server now that all sink analysis is done.
    cpg_path = state.get("joern_cpg", "")
    if cpg_path:
        stop_joern_server(cpg_path)

    if not results:
        return {
            "analysis_result": AnalysisResult(
                binary=binary,
                verdict=Verdict.Inconclusive,
                preconditions=[],
                sink_results=[],
            )
        }

    exploitable = [r for r in results if r.verdict == Verdict.Exploitable]

    if exploitable:
        # Pick the sink with the fewest present-sense preconditions as canonical.
        canonical = min(
            exploitable,
            key=lambda r: len([p for p in r.preconditions]),
        )
        verdict      = Verdict.Exploitable
        preconditions = canonical.preconditions

    elif all(r.verdict == Verdict.NotExploitable for r in results):
        verdict       = Verdict.NotExploitable
        preconditions = []

    else:
        verdict       = Verdict.Inconclusive
        # Surface the most complete hypothesis from any Inconclusive sink.
        inc = [r for r in results if r.verdict == Verdict.Inconclusive]
        preconditions = max(inc, key=lambda r: len(r.preconditions)).preconditions

    return {
        "analysis_result": AnalysisResult(
            binary=binary,
            verdict=verdict,
            preconditions=preconditions,
            sink_results=results,
        )
    }
