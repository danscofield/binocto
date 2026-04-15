"""Evaluation scoring: compare agent output against ground truth.

The agent produces typed ConfigurationOption objects and a Verdict.
The C/I/S axis labels from the corpus taxonomy are DERIVED here from
those typed outputs — they are never seen by the agent itself.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from models import AnalysisResult, ConfigurationOption, ConfigurationType, Sense, Verdict


# ---------------------------------------------------------------------------
# Axis inference from agent output
# (these are scoring utilities, not agent logic)
# ---------------------------------------------------------------------------

def infer_c_axis(preconditions: List[ConfigurationOption]) -> str:
    """Infer C-axis label from precondition types.

    C1   – one CLI flag (sense: present)
    C1b  – two CLI flags
    C1c  – three or more CLI flags
    C2   – at least one config-file key (no runtime_state)
    C3   – config-file key + runtime_state endpoint
    """
    present = [p for p in preconditions if p.sense == Sense.present]
    flags   = [p for p in present if p.configuration_type == ConfigurationType.flag]
    files   = [p for p in present if p.configuration_type == ConfigurationType.file]
    states  = [p for p in present if p.configuration_type == ConfigurationType.runtime_state]

    if states:
        return "C3"
    if files:
        return "C2"
    if len(flags) >= 3:
        return "C1c"
    if len(flags) == 2:
        return "C1b"
    return "C1"


def infer_s_axis(preconditions: List[ConfigurationOption], sanitization: Optional[dict] = None) -> str:
    """Infer S-axis label from absent-sense preconditions and sanitization evidence.

    S1  – no sanitization present
    S2  – sanitization present but bypassable (not config-gated)
    S3  – config-gated sanitization (an absent-sense precondition exists, or
          sanitization evidence shows config_gated=True)

    When sanitization evidence from assess_sanitization is available (stored in
    the canonical SinkResult's evidence dict), it disambiguates S1 vs S2 — both
    produce no absent-sense preconditions, but S2 has bypassable=True in evidence.
    """
    absent = [p for p in preconditions if p.sense == Sense.absent]
    if absent:
        return "S3"

    san = sanitization or {}
    if san.get("config_gated"):
        return "S3"
    if san.get("sanitization_present") and san.get("bypassable"):
        return "S2"
    return "S1"


def infer_i_axis(result: AnalysisResult) -> str:
    """Infer I-axis label from hop_count stored in the canonical sink's evidence.

    I1  – 1 hop  (input received and passed directly to sink in the same function)
    I2  – 2 hops (one intermediate function between receiver and sink)
    I3  – 3+ hops (multi-hop taint path through two or more intermediate functions)

    Prefers the Exploitable sink with fewest preconditions; falls back to the
    first available sink result when no Exploitable result exists.
    """
    exploitable = [sr for sr in result.sink_results if sr.verdict == Verdict.Exploitable]
    if exploitable:
        canonical = min(exploitable, key=lambda sr: len(sr.preconditions))
    elif result.sink_results:
        canonical = result.sink_results[0]
    else:
        return "I1"

    hop_count = canonical.evidence.get("input_path", {}).get("hop_count", 1)
    try:
        hop_count = int(hop_count)
    except (TypeError, ValueError):
        hop_count = 1

    if hop_count <= 1:
        return "I1"
    if hop_count == 2:
        return "I2"
    return "I3"


# ---------------------------------------------------------------------------
# Precondition comparison
# ---------------------------------------------------------------------------

def preconditions_match(
    predicted: List[ConfigurationOption],
    expected:  List[ConfigurationOption],
) -> Tuple[bool, Dict[str, Any]]:
    """Compare predicted preconditions against expected (ground truth).

    Returns (recall_perfect: bool, details: dict).

    recall_perfect is True when every expected option is covered by at least
    one predicted option — i.e. recall == 1.0.

    details includes:
      matched    – expected options that were correctly predicted
      unmatched  – expected options the agent missed (recall gaps)
      extra      – predicted options that match no expected option (precision gaps)
      recall     – fraction of expected options covered (0.0–1.0)
      precision  – fraction of predicted options that match an expected option (0.0–1.0)

    Matching strategy: for each expected option, find a predicted option where all
    non-null expected fields match.  This allows the agent to be more specific
    (e.g. predicting a value when the ground truth only requires presence) without
    being penalised.
    """
    matched:   List[ConfigurationOption] = []
    unmatched: List[ConfigurationOption] = []

    for exp in expected:
        found = any(_option_matches(pred, exp) for pred in predicted)
        (matched if found else unmatched).append(exp)

    extra = [p for p in predicted if not any(_option_matches(p, exp) for exp in expected)]

    n_expected  = len(expected)
    n_predicted = len(predicted)
    n_matched   = len(matched)

    recall    = n_matched / n_expected  if n_expected  > 0 else 1.0
    precision = n_matched / n_predicted if n_predicted > 0 else 1.0

    return (len(unmatched) == 0), {
        "matched":   [o.model_dump() for o in matched],
        "unmatched": [o.model_dump() for o in unmatched],
        "extra":     [o.model_dump() for o in extra],
        "recall":    recall,
        "precision": precision,
    }


def _option_matches(pred: ConfigurationOption, exp: ConfigurationOption) -> bool:
    if pred.configuration_type != exp.configuration_type:
        return False
    if pred.configuration_parameter != exp.configuration_parameter:
        return False
    if pred.sense != exp.sense:
        return False
    # For runtime_state preconditions the token value is runtime-configurable
    # (read from a config file at startup) and cannot be recovered from static
    # binary analysis alone.  Match on route/parameter only — do not require
    # the predicted token to equal the ground-truth token.
    if exp.configuration_type == ConfigurationType.runtime_state:
        return True
    # For flags and file keys: None in expected means "presence only"; otherwise must match.
    if exp.configuration_value is not None:
        if pred.configuration_value != exp.configuration_value:
            return False
    return True


# ---------------------------------------------------------------------------
# Ground-truth loading
# ---------------------------------------------------------------------------

def load_ground_truth(sample_dir: str | Path) -> Dict[str, Any]:
    """Load ground_truth.json for a sample directory."""
    path = Path(sample_dir) / "ground_truth.json"
    with open(path) as fh:
        return json.load(fh)


def ground_truth_to_options(gt: Dict[str, Any]) -> List[ConfigurationOption]:
    """Convert ground_truth preconditions list to ConfigurationOption objects."""
    options = []
    for pc in gt.get("preconditions", []):
        options.append(ConfigurationOption(
            configuration_type=ConfigurationType(pc["configuration_type"]),
            configuration_parameter=pc["configuration_parameter"],
            configuration_value=pc.get("configuration_value"),
            sense=Sense(pc.get("sense", "present")),
        ))
    return options


# ---------------------------------------------------------------------------
# Top-level scorer
# ---------------------------------------------------------------------------

def score_result(
    result:     AnalysisResult,
    sample_dir: str | Path,
) -> Dict[str, Any]:
    """Compare an AnalysisResult against the ground truth for a sample.

    Returns a score dict with keys:
      sample, verdict_correct, preconditions_correct,
      precondition_recall, precondition_precision,
      predicted_c_axis, expected_c_axis,
      predicted_s_axis, expected_s_axis,
      predicted_i_axis, expected_i_axis,
      false_exploitable, false_not_exploitable,
      match_details
    """
    gt       = load_ground_truth(sample_dir)
    exp_opts = ground_truth_to_options(gt)

    expected_verdict = gt.get("verified", "Exploitable")
    predicted_verdict = result.verdict.value

    verdict_correct      = (predicted_verdict == expected_verdict)
    false_exploitable    = (predicted_verdict == "Exploitable"    and expected_verdict == "NotExploitable")
    false_not_exploitable = (predicted_verdict == "NotExploitable" and expected_verdict == "Exploitable")
    gave_up              = (predicted_verdict == "Inconclusive"   and expected_verdict != "Inconclusive")

    # When multiple exploitable sinks exist, aggregate_results picks the one
    # with fewest preconditions as canonical — which may be a different feature
    # (e.g. a trivially-gated CGI handler) rather than the intended target.
    # Score against ALL exploitable sink results and take the best recall.
    exploitable_srs = [sr for sr in result.sink_results if sr.verdict == Verdict.Exploitable]
    if exploitable_srs:
        best_pcs       = result.preconditions
        best_recall, best_details = preconditions_match(result.preconditions, exp_opts)
        for sr in exploitable_srs:
            ok, det = preconditions_match(sr.preconditions, exp_opts)
            if det["recall"] > best_details["recall"]:
                best_recall, best_details, best_pcs = ok, det, sr.preconditions
        recall_perfect, match_details = best_recall, best_details
        scored_preconditions = best_pcs
    else:
        recall_perfect, match_details = preconditions_match(result.preconditions, exp_opts)
        scored_preconditions = result.preconditions

    # Extract sanitization evidence from the best-matching sink result.
    canonical_sr = (
        max(exploitable_srs,
            key=lambda sr: preconditions_match(sr.preconditions, exp_opts)[1]["recall"])
        if exploitable_srs else (result.sink_results[0] if result.sink_results else None)
    )
    sanitization_evidence = canonical_sr.evidence.get("sanitization") if canonical_sr else None

    predicted_c = infer_c_axis(scored_preconditions)
    predicted_s = infer_s_axis(scored_preconditions, sanitization_evidence)
    predicted_i = infer_i_axis(result)

    expected_axes = gt.get("axes", {})

    return {
        "sample":                 gt.get("sample", Path(sample_dir).name),
        "verdict_correct":        verdict_correct,
        "preconditions_correct":  recall_perfect,
        "precondition_recall":    match_details["recall"],
        "precondition_precision": match_details["precision"],
        "predicted_c_axis":       predicted_c,
        "expected_c_axis":        expected_axes.get("C", "?"),
        "predicted_s_axis":       predicted_s,
        "expected_s_axis":        expected_axes.get("S", "?"),
        "predicted_i_axis":       predicted_i,
        "expected_i_axis":        expected_axes.get("I", "?"),
        "false_exploitable":      false_exploitable,
        "false_not_exploitable":  false_not_exploitable,
        "gave_up":                gave_up,
        "match_details":          match_details,
    }


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def _percentile(data: List[float], p: float) -> Optional[float]:
    """Return the p-th percentile of *data* (0–100). Returns None if empty."""
    if not data:
        return None
    s = sorted(data)
    # nearest-rank method
    idx = max(0, int(p / 100 * len(s)) - 1)
    return s[idx]


def aggregate_scores(scores: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Summarise a list of per-sample score dicts into corpus-level metrics."""
    n = len(scores)
    if n == 0:
        return {}

    verdict_correct = sum(1 for s in scores if s["verdict_correct"])
    prec_correct    = sum(1 for s in scores if s["preconditions_correct"])
    both_correct    = sum(1 for s in scores if s["verdict_correct"] and s["preconditions_correct"])

    false_exploitable     = sum(1 for s in scores if s.get("false_exploitable"))
    false_not_exploitable = sum(1 for s in scores if s.get("false_not_exploitable"))
    gave_up               = sum(1 for s in scores if s.get("gave_up"))

    c_axis_correct = sum(1 for s in scores if s["predicted_c_axis"] == s["expected_c_axis"])
    s_axis_correct = sum(1 for s in scores if s["predicted_s_axis"] == s["expected_s_axis"])
    i_axis_correct = sum(1 for s in scores if s.get("predicted_i_axis") == s.get("expected_i_axis"))

    recalls    = [s["precondition_recall"]    for s in scores if "precondition_recall"    in s]
    precisions = [s["precondition_precision"] for s in scores if "precondition_precision" in s]

    durations = [s["duration_s"] for s in scores if s.get("duration_s") is not None]

    return {
        "n":                         n,
        # Verdict
        "verdict_accuracy":          verdict_correct / n,
        "false_exploitable_count":   false_exploitable,
        "false_not_exploitable_count": false_not_exploitable,
        "gave_up_count":             gave_up,
        # Preconditions
        "precondition_accuracy":     prec_correct / n,
        "full_accuracy":             both_correct / n,
        "avg_precondition_recall":   sum(recalls)    / len(recalls)    if recalls    else None,
        "avg_precondition_precision": sum(precisions) / len(precisions) if precisions else None,
        # Axes
        "c_axis_accuracy":           c_axis_correct / n,
        "s_axis_accuracy":           s_axis_correct / n,
        "i_axis_accuracy":           i_axis_correct / n,
        # Duration
        "duration_p50":              _percentile(durations, 50),
        "duration_p95":              _percentile(durations, 95),
    }
