"""record_sink node: terminal node for per-sink subgraph.

Called when:
  - causal_verify confirmed Exploitable or NotExploitable (result already written)
  - input not reachable → NotExploitable
  - causal_verify exhausted MAX_VERIFY_ATTEMPTS without a conclusive result → Inconclusive

record_sink_success and record_sink_not_reachable write or pass through a result.
record_sink_inconclusive writes the final Inconclusive result.
"""

from __future__ import annotations

from models import SinkResult, Verdict
from state import MAX_VERIFY_ATTEMPTS, SinkState


def record_sink_not_reachable(state: SinkState) -> dict:
    """Fast-fail path: attacker cannot reach the sink."""
    result = SinkResult(
        sink=state["sink"],
        verdict=Verdict.NotExploitable,
        preconditions=[],
        attempts=0,
        evidence={"reason": "input_not_reachable"},
    )
    return {"results": [result]}


def record_sink_inconclusive(state: SinkState) -> dict:
    """Causal verify exhausted all attempts without a conclusive result."""
    result = SinkResult(
        sink=state["sink"],
        verdict=Verdict.Inconclusive,
        preconditions=state.get("precondition_hypothesis", []),
        attempts=state.get("verify_attempts", MAX_VERIFY_ATTEMPTS),
        evidence={
            "gate_source":       state.get("gate_source"),
            "last_failure":      state.get("verify_failure_reason"),
            "gate_conditions":   state.get("gate_conditions", []),
        },
    )
    return {"results": [result]}


def record_sink_success(state: SinkState) -> dict:
    """Causal verify produced a terminal verdict — result already in state.results."""
    return {}
