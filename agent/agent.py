"""LangGraph vulnerability analysis agent.

Graph structure
---------------

Main graph (GraphState):
  setup → enumerate_sinks → [fan out via Send] → aggregate_results → END

Per-sink subgraph (SinkState) — compiled and dispatched as a node:
  check_input_reach
    ↓ reachable          ↓ not reachable
  trace_and_classify_gate  record_sink_not_reachable → END
    ↓
  trace_input_path
    ↓
  assess_sanitization
    ↓
  ┌─ synthesize_preconditions ◄─────────────────────┐
  │    ↓                                             │
  │  causal_verify                                   │
  │    ↓ success           ↓ failure, attempts < MAX │
  │  record_sink_success   (loop back, revise)  ─────┘
  │                        ↓ failure, attempts >= MAX
  │                       record_sink_inconclusive
  └──────────────────────────────────────────────────

Usage
-----
    from agent import build_agent
    graph = build_agent()
    result = graph.invoke({"binary": "/path/to/binary"})
    print(result["analysis_result"])
"""

from __future__ import annotations

import operator
from typing import Annotated, List

from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from models import SinkResult, Verdict
from nodes import (
    aggregate_results_node,
    assess_sanitization_node,
    causal_verify_node,
    check_input_reach_node,
    enumerate_sinks_node,
    record_sink_inconclusive,
    record_sink_not_reachable,
    record_sink_success,
    setup_node,
    synthesize_preconditions_node,
    trace_and_classify_gate_node,
    trace_input_path_node,
)
from state import MAX_VERIFY_ATTEMPTS, GraphState, SinkState


# ---------------------------------------------------------------------------
# Routing functions
# ---------------------------------------------------------------------------

def route_sinks(state: GraphState):
    """Fan out one per-sink subgraph invocation per discovered sink."""
    if not state.get("sink_list"):
        # No dangerous call sites found — route directly to aggregate so that
        # analysis_result is always set (as Inconclusive) rather than staying None.
        return "aggregate_results"

    dispatches = []
    for sink in state["sink_list"]:
        sink_state: SinkState = {
            "binary":                  state["binary"],
            "joern_cpg":               state["joern_cpg"],
            "sink":                    sink,
            "input_reachable":         None,
            "gate_source":             None,
            "gate_conditions":         [],
            "input_path":              None,
            "sanitization":            None,
            "causal_chain":            None,
            "precondition_hypothesis": [],
            "verify_attempts":         0,
            "verify_failure_reason":   None,
            "results":                 [],
        }
        dispatches.append(Send("check_input_reach", sink_state))
    return dispatches


def route_after_reach_check(state: SinkState):
    if state.get("input_reachable"):
        return "trace_and_classify_gate"
    return "record_sink_not_reachable"


def route_after_causal_verify(state: SinkState):
    # causal_verify_node sets failure_reason=None on success (Exploitable verdict),
    # a CausalFailure value on failure (Inconclusive), or also sets results on
    # NotExploitable (no retry for that case — loop exits via inconclusive path).
    failure  = state.get("verify_failure_reason")
    attempts = state.get("verify_attempts", 0)

    if failure is None:
        return "record_sink_success"
    if attempts < MAX_VERIFY_ATTEMPTS:
        return "synthesize_preconditions"
    return "record_sink_inconclusive"


# ---------------------------------------------------------------------------
# Per-sink subgraph
# ---------------------------------------------------------------------------

def build_sink_subgraph() -> object:
    builder = StateGraph(SinkState)

    builder.add_node("check_input_reach",        check_input_reach_node)
    builder.add_node("trace_and_classify_gate",  trace_and_classify_gate_node)
    builder.add_node("trace_input_path",         trace_input_path_node)
    builder.add_node("assess_sanitization",      assess_sanitization_node)
    builder.add_node("synthesize_preconditions", synthesize_preconditions_node)
    builder.add_node("causal_verify",            causal_verify_node)
    builder.add_node("record_sink_not_reachable", record_sink_not_reachable)
    builder.add_node("record_sink_success",      record_sink_success)
    builder.add_node("record_sink_inconclusive", record_sink_inconclusive)

    builder.add_edge(START, "check_input_reach")

    builder.add_conditional_edges(
        "check_input_reach",
        route_after_reach_check,
        {
            "trace_and_classify_gate":   "trace_and_classify_gate",
            "record_sink_not_reachable": "record_sink_not_reachable",
        },
    )

    builder.add_edge("trace_and_classify_gate", "trace_input_path")
    builder.add_edge("trace_input_path",        "assess_sanitization")
    builder.add_edge("assess_sanitization",  "synthesize_preconditions")
    builder.add_edge("synthesize_preconditions", "causal_verify")

    builder.add_conditional_edges(
        "causal_verify",
        route_after_causal_verify,
        {
            "record_sink_success":       "record_sink_success",
            "synthesize_preconditions":  "synthesize_preconditions",
            "record_sink_inconclusive":  "record_sink_inconclusive",
        },
    )

    builder.add_edge("record_sink_not_reachable", END)
    builder.add_edge("record_sink_success",       END)
    builder.add_edge("record_sink_inconclusive",  END)

    return builder.compile()


# ---------------------------------------------------------------------------
# Main graph
# ---------------------------------------------------------------------------

def build_agent():
    """Compile and return the full analysis graph."""
    sink_subgraph = build_sink_subgraph()

    builder = StateGraph(GraphState)

    builder.add_node("setup",            setup_node)
    builder.add_node("enumerate_sinks",  enumerate_sinks_node)
    builder.add_node("check_input_reach", sink_subgraph)   # dispatched via Send
    builder.add_node("aggregate_results", aggregate_results_node)

    builder.add_edge(START, "setup")
    builder.add_edge("setup", "enumerate_sinks")

    builder.add_conditional_edges(
        "enumerate_sinks",
        route_sinks,
        ["check_input_reach", "aggregate_results"],
    )

    # After all parallel sink branches complete, aggregate
    builder.add_edge("check_input_reach", "aggregate_results")
    builder.add_edge("aggregate_results", END)

    return builder.compile()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def analyse(binary: str) -> dict:
    """Run the full analysis pipeline on *binary*.

    Returns the final GraphState, which includes ``analysis_result``
    (an AnalysisResult) and ``results`` (List[SinkResult]).
    """
    graph = build_agent()
    return graph.invoke({
        "binary":    binary,
        "joern_cpg": "",
        "sink_list": [],
        "results":   [],
    })
