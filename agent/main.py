#!/usr/bin/env python3
"""Run the vulnerability analysis agent against a binary.

Usage:
    python main.py <binary> [--sample-dir <path>]

    <binary>        path to the compiled binary to analyse
    --sample-dir    optional: path to a corpus sample directory
                    (must contain ground_truth.json); enables scoring

Environment:
    ANTHROPIC_API_KEY   required
    JOERN_BIN           path to joern executable      (default: joern)
    JOERN_PARSE_BIN     path to joern-parse executable (default: joern-parse)
    CLAUDE_MODEL        model override                 (default: claude-sonnet-4-6)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import textwrap
from pathlib import Path

# Make sure the agent package is importable when run directly.
sys.path.insert(0, str(Path(__file__).parent))

from models import AnalysisResult, ConfigurationType, Sense, Verdict
from scoring import ground_truth_to_options, load_ground_truth, score_result


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def _verdict_colour(verdict: Verdict) -> str:
    colours = {
        Verdict.Exploitable:    "\033[91m",  # red
        Verdict.NotExploitable: "\033[92m",  # green
        Verdict.Inconclusive:   "\033[93m",  # yellow
    }
    reset = "\033[0m"
    return f"{colours.get(verdict, '')}{verdict.value}{reset}"


def print_result(result: AnalysisResult) -> None:
    print()
    print("=" * 60)
    print(f"  Binary : {result.binary}")
    print(f"  Verdict: {_verdict_colour(result.verdict)}")
    print("=" * 60)

    if result.preconditions:
        print("\nPreconditions:")
        for opt in result.preconditions:
            sense_tag = "PRESENT" if opt.sense == Sense.present else "ABSENT "
            if opt.configuration_type == ConfigurationType.flag:
                val_str = opt.configuration_parameter
            elif opt.configuration_type == ConfigurationType.file:
                val_str = f"{opt.configuration_parameter}={opt.configuration_value}"
            else:
                val_str = (f"{opt.configuration_parameter}"
                           + (f"  token={opt.configuration_value}" if opt.configuration_value else ""))
            print(f"  [{sense_tag}]  {opt.configuration_type.value:14s}  {val_str}")
    else:
        print("\nPreconditions: (none)")

    if result.sink_results:
        print(f"\nSinks analysed: {len(result.sink_results)}")
        for sr in result.sink_results:
            marker = {"Exploitable": "✓", "NotExploitable": "✗", "Inconclusive": "?"}.get(
                sr.verdict.value, "?"
            )
            print(f"  [{marker}] {sr.sink.function}() in {sr.sink.caller}"
                  f"  addr={hex(sr.sink.addr)}  attempts={sr.attempts}")
    print()


def print_score(score: dict) -> None:
    ok   = "\033[92m✓\033[0m"
    fail = "\033[91m✗\033[0m"

    verdict_sym = ok if score["verdict_correct"]       else fail
    prec_sym    = ok if score["preconditions_correct"] else fail

    print("Scoring against ground truth")
    print("-" * 40)
    print(f"  Verdict       {verdict_sym}  (predicted={score.get('predicted_verdict','?')},"
          f" expected={score.get('expected_verdict','?')})")
    print(f"  Preconditions {prec_sym}")
    print(f"  C-axis        predicted={score['predicted_c_axis']}"
          f"  expected={score['expected_c_axis']}"
          + (" ✓" if score["predicted_c_axis"] == score["expected_c_axis"] else " ✗"))
    print(f"  S-axis        predicted={score['predicted_s_axis']}"
          f"  expected={score['expected_s_axis']}"
          + (" ✓" if score["predicted_s_axis"] == score["expected_s_axis"] else " ✗"))

    details = score.get("match_details", {})
    if details.get("unmatched"):
        print("\n  Unmatched expected preconditions:")
        for u in details["unmatched"]:
            print(f"    - {u}")
    if details.get("extra"):
        print("\n  Extra predicted preconditions (not in ground truth):")
        for e in details["extra"]:
            print(f"    + {e}")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the vulnerability analysis agent against a binary.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python main.py /path/to/darkhttpd
              python main.py /path/to/darkhttpd \\
                  --sample-dir ../corpus/samples/001_darkhttpd_C1I1S1
        """),
    )
    parser.add_argument("binary",     help="Path to the binary to analyse")
    parser.add_argument("--sample-dir", metavar="DIR",
                        help="Corpus sample directory containing ground_truth.json")
    parser.add_argument("--json",    action="store_true",
                        help="Also dump the full result as JSON to stdout")
    parser.add_argument("--max-iter", type=int, default=None, metavar="N",
                        help="Max tool-call iterations per agent node "
                             "(default: AGENT_MAX_ITER env var or 100)")
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("-v", "--verbose", action="store_true",
                           help="Show node transitions, cache hits, tool call names")
    verbosity.add_argument("-vv", "--debug",  action="store_true",
                           help="Show full tool outputs and LLM responses")
    args = parser.parse_args()

    if args.max_iter is not None:
        os.environ["AGENT_MAX_ITER"] = str(args.max_iter)

    # Logging setup
    if args.debug:
        level  = logging.DEBUG
        fmt    = "%(asctime)s %(levelname)-5s %(name)s  %(message)s"
        datefmt = "%H:%M:%S"
    elif args.verbose:
        level  = logging.INFO
        fmt    = "%(asctime)s  %(message)s"
        datefmt = "%H:%M:%S"
    else:
        level  = logging.WARNING
        fmt    = "%(message)s"
        datefmt = None

    logging.basicConfig(level=level, format=fmt, datefmt=datefmt, stream=sys.stderr)
    # Suppress noisy third-party loggers unless in debug mode
    if not args.debug:
        for noisy in ("httpx", "httpcore", "anthropic", "langchain", "langgraph"):
            logging.getLogger(noisy).setLevel(logging.WARNING)

    binary = os.path.abspath(args.binary)
    if not os.path.isfile(binary):
        sys.exit(f"error: binary not found: {binary}")

    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("error: ANTHROPIC_API_KEY environment variable not set")

    # Lazy import so startup errors are readable before the heavy deps load.
    from agent import analyse

    print(f"Analysing {binary} …")
    state = analyse(binary)

    result: AnalysisResult = state.get("analysis_result")
    if result is None:
        sys.exit("error: agent returned no analysis_result")

    print_result(result)

    if args.sample_dir:
        sample_dir = Path(args.sample_dir)
        if not (sample_dir / "ground_truth.json").exists():
            print(f"warning: no ground_truth.json in {sample_dir}, skipping scoring")
        else:
            gt = load_ground_truth(sample_dir)
            score = score_result(result, sample_dir)
            # Patch in the string verdicts for display
            score["predicted_verdict"] = result.verdict.value
            score["expected_verdict"]  = gt.get("verified", "?")
            print_score(score)

    if args.json:
        print(json.dumps(result.model_dump(), indent=2))


if __name__ == "__main__":
    main()
