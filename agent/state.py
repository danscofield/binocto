from __future__ import annotations

import operator
from typing import Annotated, List, Optional, TypedDict

from models import AnalysisResult, ConfigurationOption, Sink, SinkResult

MAX_VERIFY_ATTEMPTS = 3


def _keep_last(a, b):
    """Reducer for fields that multiple parallel branches write identically.

    All per-sink subgraphs receive the same binary path and CPG path, so any
    of their writes is correct.  This reducer avoids InvalidUpdateError when
    N sinks complete in the same step.
    """
    return b if b is not None else a


class GraphState(TypedDict):
    """Top-level graph state shared across the main graph.

    ``results`` uses operator.add so that parallel per-sink branches each
    append their SinkResult without clobbering one another.

    ``binary`` and ``joern_cpg`` use _keep_last because each per-sink
    subgraph writes the same values back; without a reducer, parallel
    completions raise InvalidUpdateError.
    """
    binary:          Annotated[str, _keep_last]
    joern_cpg:       Annotated[str, _keep_last]        # path to pre-built CPG (.bin)
    sink_list:       List[Sink]
    results:         Annotated[List[SinkResult], operator.add]
    analysis_result: Optional[AnalysisResult]          # written by aggregate_results


class SinkState(TypedDict):
    """Per-sink analysis state.  One instance per sink dispatched via Send.

    Includes ``results`` with the same reducer so the subgraph's final
    record_sink node can write back into the parent graph's list.
    """
    # Propagated from GraphState
    binary:    str
    joern_cpg: str

    # The sink being analysed
    sink: Sink

    # Populated by analysis nodes (reset at sink boundary)
    input_reachable:       Optional[bool]
    gate_source:           Optional[str]   # "cli_flag" | "config_file" | "runtime_sequence"
    gate_conditions:       list            # raw structured findings from trace_gate
    input_path:            Optional[dict]  # from trace_input_path
    sanitization:          Optional[dict]  # from assess_sanitization
    causal_chain:          Optional[dict]  # from synthesize_preconditions

    # Hypothesis / verify loop
    precondition_hypothesis: List[ConfigurationOption]
    verify_attempts:         int
    verify_failure_reason:   Optional[str]  # CausalFailure value

    # Written by record_sink; merged into GraphState.results via add reducer
    results: Annotated[List[SinkResult], operator.add]
