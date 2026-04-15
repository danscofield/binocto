#!/usr/bin/env python3
"""Batch corpus evaluation runner.

Runs the agent against N random samples (or the entire corpus) in parallel,
scores each result against ground truth, and prints a summary table.

Usage:
    # Run all samples (4 workers by default)
    python eval.py --all

    # Run 20 random samples
    python eval.py -n 20

    # Run specific samples by number or full name
    python eval.py --sample 001 117 120

    # Filter by axis label(s) and/or server name (AND-ed)
    python eval.py --all --filter C2
    python eval.py --all --filter C3 --filter darkhttpd

    # Resume an interrupted run (skips completed samples)
    python eval.py --all --resume

    # Just aggregate and display existing results (no new runs)
    python eval.py --summary

    # Adjust concurrency and timeout
    python eval.py -n 20 --workers 8 --timeout 900

Environment:
    ANTHROPIC_API_KEY   required
    JOERN_BIN           path to joern executable       (default: joern)
    JOERN_PARSE_BIN     path to joern-parse executable (default: joern-parse)
    CLAUDE_MODEL        model override                  (default: claude-sonnet-4-6)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional

# Make sure the agent package is importable when run directly.
sys.path.insert(0, str(Path(__file__).parent))

CORPUS_SAMPLES = Path(__file__).parent.parent / "corpus" / "samples"
DEFAULT_OUT_DIR = Path(__file__).parent / "eval_results"
DEFAULT_WORKERS = 4
DEFAULT_TIMEOUT = 600  # seconds per sample

log = logging.getLogger("eval")


# ---------------------------------------------------------------------------
# Per-sample log routing
# ---------------------------------------------------------------------------

class _ThreadFilter(logging.Filter):
    """Pass only log records emitted by a specific thread."""
    def __init__(self, tid: int) -> None:
        self._tid = tid

    def filter(self, record: logging.LogRecord) -> bool:
        return record.thread == self._tid


def _install_sample_log_handler(log_path: Path) -> logging.FileHandler:
    """Create a DEBUG file handler scoped to the current thread."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    h = logging.FileHandler(log_path, mode="w", encoding="utf-8")
    h.setLevel(logging.DEBUG)
    h.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-5s %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    ))
    h.addFilter(_ThreadFilter(threading.get_ident()))
    logging.getLogger().addHandler(h)
    # Ensure the root logger passes DEBUG records through to our handler.
    root = logging.getLogger()
    if root.level > logging.DEBUG:
        root.setLevel(logging.DEBUG)
    return h


def _remove_sample_log_handler(h: logging.FileHandler) -> None:
    logging.getLogger().removeHandler(h)
    h.close()


# ---------------------------------------------------------------------------
# Sample discovery
# ---------------------------------------------------------------------------

def discover_samples(corpus_dir: Path = CORPUS_SAMPLES) -> List[Path]:
    """Return all sample directories that contain a ground_truth.json."""
    dirs = sorted(
        d for d in corpus_dir.iterdir()
        if d.is_dir() and (d / "ground_truth.json").exists()
    )
    return dirs


def find_binary(sample_dir: Path) -> Path:
    """Locate the pre-built binary in a sample directory."""
    candidates = [
        p for p in sample_dir.iterdir()
        if p.is_file()
        and os.access(p, os.X_OK)
        and p.suffix == ""
        and p.name not in {"PROVENANCE"}
    ]
    if not candidates:
        raise FileNotFoundError(f"no executable binary found in {sample_dir}")
    return sorted(candidates)[0]


def filter_samples(
    samples: List[Path],
    filters: List[str],
) -> List[Path]:
    """Keep only samples whose name contains ALL filter strings.

    Filters are matched case-insensitively against the sample directory name,
    so "C2", "darkhttpd", "S3", "I1" all work as axis or server name filters.
    """
    result = samples
    for f in filters:
        fl = f.lower()
        result = [s for s in result if fl in s.name.lower()]
    return result


def select_samples(
    all_samples: List[Path],
    *,
    run_all: bool = False,
    n: Optional[int] = None,
    ids: Optional[List[str]] = None,
    filters: Optional[List[str]] = None,
    seed: Optional[int] = None,
) -> List[Path]:
    """Apply filters and selection to the sample list."""
    samples = all_samples

    if filters:
        samples = filter_samples(samples, filters)

    if ids:
        # Match by numeric prefix or full name
        selected = []
        for id_str in ids:
            matches = [
                s for s in samples
                if s.name == id_str or s.name.startswith(id_str.zfill(3) + "_")
            ]
            if not matches:
                log.warning("no sample matching %r", id_str)
            selected.extend(matches)
        return selected

    if run_all:
        return samples

    if n is not None:
        rng = random.Random(seed)
        return rng.sample(samples, min(n, len(samples)))

    return samples


# ---------------------------------------------------------------------------
# Per-sample runner
# ---------------------------------------------------------------------------

def run_sample(
    sample_dir: Path,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    log_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Run the agent on one sample and return a result record.

    The record always has:
      sample       sample name
      binary       path to binary
      duration_s   wall-clock seconds
      error        null or error string
      result       AnalysisResult dict (null on error)
      score        score dict (null on error or no ground truth)
      log_path     path to per-sample debug log (null if log_dir not set)
    """
    sample_name = sample_dir.name
    t0 = time.monotonic()

    record: Dict[str, Any] = {
        "sample":     sample_name,
        "binary":     None,
        "duration_s": None,
        "error":      None,
        "result":     None,
        "score":      None,
        "log_path":   None,
    }

    # Per-sample debug log — captures all agent/joern DEBUG output for this thread.
    log_handler = None
    if log_dir is not None:
        log_path = log_dir / f"{sample_name}.log"
        log_handler = _install_sample_log_handler(log_path)
        record["log_path"] = str(log_path)

    try:
        binary = find_binary(sample_dir)
        record["binary"] = str(binary)

        # Import here so the heavy deps only load in worker threads.
        from agent import analyse
        from scoring import score_result

        log.info("[%s] starting", sample_name)
        state = analyse(str(binary))
        analysis_result = state.get("analysis_result")

        if analysis_result is None:
            raise RuntimeError("agent returned no analysis_result")

        record["result"] = analysis_result.model_dump(mode="json")

        # Score against ground truth.
        gt_path = sample_dir / "ground_truth.json"
        if gt_path.exists():
            score = score_result(analysis_result, sample_dir)
            score["predicted_verdict"] = analysis_result.verdict.value
            score["duration_s"] = record.get("duration_s")
            with open(gt_path) as fh:
                gt = json.load(fh)
            score["expected_verdict"] = gt.get("verified", "?")
            record["score"] = score

        log.info("[%s] done  verdict=%s", sample_name, analysis_result.verdict.value)

    except Exception as exc:
        record["error"] = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}"
        log.error("[%s] FAILED: %s", sample_name, exc)

    finally:
        record["duration_s"] = round(time.monotonic() - t0, 1)
        if log_handler is not None:
            _remove_sample_log_handler(log_handler)

    return record


def save_record(record: Dict[str, Any], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{record['sample']}.json"
    path.write_text(json.dumps(record, indent=2))
    return path


def load_existing(out_dir: Path) -> Dict[str, Dict[str, Any]]:
    """Load all existing result records from out_dir, keyed by sample name."""
    results = {}
    if out_dir.exists():
        for p in out_dir.glob("*.json"):
            try:
                data = json.loads(p.read_text())
                results[data["sample"]] = data
            except Exception:
                pass
    return results


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

_RESET  = "\033[0m"
_RED    = "\033[91m"
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_CYAN   = "\033[96m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"


def _col(text: str, colour: str) -> str:
    return f"{colour}{text}{_RESET}"


def _ok(b: bool) -> str:
    return _col("✓", _GREEN) if b else _col("✗", _RED)


def _verdict_col(v: str) -> str:
    colours = {
        "Exploitable":    _RED,
        "NotExploitable": _GREEN,
        "Inconclusive":   _YELLOW,
    }
    return _col(v, colours.get(v, ""))


def print_progress(record: Dict[str, Any]) -> None:
    """Print a one-line status after each sample completes."""
    name = record["sample"]
    dur  = record["duration_s"]
    err  = record["error"]
    sc   = record.get("score") or {}

    if err:
        status = _col("TIMEOUT" if "TimeoutError" in (err or "") else "ERROR", _RED)
        dur_str = f"{dur:.0f}s" if dur is not None else "?"
        log_hint = f"  log={record['log_path']}" if record.get("log_path") else ""
        print(f"  {name:<40s}  {status}  ({dur_str}){log_hint}", flush=True)
        return

    verdict = (record.get("result") or {}).get("verdict", "?")
    vc = _ok(sc.get("verdict_correct", False))
    pc = _ok(sc.get("preconditions_correct", False))
    pred_c = sc.get("predicted_c_axis", "?")
    exp_c  = sc.get("expected_c_axis",  "?")
    pred_s = sc.get("predicted_s_axis", "?")
    exp_s  = sc.get("expected_s_axis",  "?")
    pred_i = sc.get("predicted_i_axis", "?")
    exp_i  = sc.get("expected_i_axis",  "?")
    c_ok   = _ok(pred_c == exp_c)
    s_ok   = _ok(pred_s == exp_s)
    i_ok   = _ok(pred_i == exp_i)
    prec_p = sc.get("precondition_precision", None)
    prec_r = sc.get("precondition_recall",    None)
    prec_str = (f"{prec_p:.2f}p/{prec_r:.2f}r"
                if prec_p is not None and prec_r is not None else "?")

    print(
        f"  {name:<40s}  "
        f"v={vc} {_verdict_col(verdict):<14s}  "
        f"prec={pc} {prec_str}  "
        f"C={c_ok}{pred_c}/{exp_c}  "
        f"I={i_ok}{pred_i}/{exp_i}  "
        f"S={s_ok}{pred_s}/{exp_s}  "
        f"({dur:.0f}s)",
        flush=True,
    )


def print_summary_table(records: List[Dict[str, Any]]) -> None:
    """Print an aggregated summary of all records."""
    from scoring import aggregate_scores

    scores = [r["score"] for r in records if r.get("score")]
    errors = [r for r in records if r.get("error")]

    print()
    print(_col("=" * 70, _BOLD))
    print(_col("  CORPUS EVALUATION SUMMARY", _BOLD))
    print(_col("=" * 70, _BOLD))
    print(f"  Total samples run : {len(records)}")
    print(f"  Errors            : {len(errors)}")
    print(f"  Scored            : {len(scores)}")

    if not scores:
        print("  (no scored results to aggregate)")
        return

    agg = aggregate_scores(scores)
    n   = agg["n"]
    print()

    # Verdict
    print(f"  Verdict accuracy      : {agg['verdict_accuracy']:.1%}  "
          f"({int(agg['verdict_accuracy']*n)}/{n})")
    fne = agg["false_not_exploitable_count"]
    gu  = agg["gave_up_count"]
    if fne:
        print(f"    missed exploits     : {fne}  "
              f"(predicted NotExploitable, was Exploitable)")
    if gu:
        print(f"    gave up (Inconc.)   : {gu}  "
              f"(Inconclusive when answer was known)")

    # Preconditions
    print()
    avg_p = agg.get("avg_precondition_precision")
    avg_r = agg.get("avg_precondition_recall")
    prec_str = (f"  avg precision {avg_p:.2f} / recall {avg_r:.2f}"
                if avg_p is not None else "")
    print(f"  Precondition recall=1 : {agg['precondition_accuracy']:.1%}  "
          f"({int(agg['precondition_accuracy']*n)}/{n}){prec_str}")
    print(f"  Full accuracy (both)  : {agg['full_accuracy']:.1%}  "
          f"({int(agg['full_accuracy']*n)}/{n})")

    # Axes
    print()
    print(f"  C-axis accuracy       : {agg['c_axis_accuracy']:.1%}  "
          f"({int(agg['c_axis_accuracy']*n)}/{n})")
    print(f"  S-axis accuracy       : {agg['s_axis_accuracy']:.1%}  "
          f"({int(agg['s_axis_accuracy']*n)}/{n})")
    print(f"  I-axis accuracy       : {agg['i_axis_accuracy']:.1%}  "
          f"({int(agg['i_axis_accuracy']*n)}/{n})")

    # Duration
    p50 = agg.get("duration_p50")
    p95 = agg.get("duration_p95")
    if p50 is not None:
        print()
        print(f"  Duration p50          : {p50:.0f}s")
        print(f"  Duration p95          : {p95:.0f}s")

    # Per-C-axis breakdown
    by_c: Dict[str, List[bool]] = {}
    for s in scores:
        c = s["expected_c_axis"]
        by_c.setdefault(c, []).append(s["verdict_correct"] and s["preconditions_correct"])
    if by_c:
        print()
        print("  Full accuracy by C-axis:")
        for c, vals in sorted(by_c.items()):
            nv = len(vals)
            ok = sum(vals)
            print(f"    {c:<5s}  {ok}/{nv}  {ok/nv:.1%}")

    if errors:
        print()
        print(_col(f"  Errors ({len(errors)}):", _RED))
        for r in errors:
            err_snippet = (r["error"] or "").split("\n")[0][:80]
            print(f"    {r['sample']}: {err_snippet}")

    print(_col("=" * 70, _BOLD))
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Batch corpus evaluation for the vulnerability analysis agent.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    sel = parser.add_mutually_exclusive_group()
    sel.add_argument("--all",    action="store_true",
                     help="Run all corpus samples")
    sel.add_argument("-n",       type=int, metavar="N",
                     help="Run N randomly selected samples")
    sel.add_argument("--sample", nargs="+", metavar="ID",
                     help="Run specific samples by number or full name")
    sel.add_argument("--summary", action="store_true",
                     help="Aggregate and display existing results, no new runs")
    sel.add_argument("--rescore", action="store_true",
                     help="Re-run scoring.py against all cached results and display "
                          "the summary; does not re-run the agent or modify saved JSONs")

    parser.add_argument("--filter", action="append", metavar="LABEL", default=[],
                        help="Filter samples by axis label or server name "
                             "(AND-ed; repeatable). E.g. --filter C2 --filter darkhttpd")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, metavar="W",
                        help=f"Parallel workers (default: {DEFAULT_WORKERS})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, metavar="SEC",
                        help=f"Timeout per sample in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--max-iter", type=int, default=None, metavar="N",
                        help="Max tool-call iterations per agent node "
                             "(default: AGENT_MAX_ITER env var or 100)")
    parser.add_argument("--corpus-dir", type=Path, default=CORPUS_SAMPLES, metavar="DIR",
                        help="Path to corpus samples directory")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR, metavar="DIR",
                        help=f"Directory for result JSONs (default: {DEFAULT_OUT_DIR})")
    parser.add_argument("--log-dir", type=Path, default=None, metavar="DIR",
                        help="Write per-sample DEBUG logs here (one file per sample). "
                             "Defaults to <out-dir>/logs/ when --logs is set.")
    parser.add_argument("--logs", action="store_true",
                        help="Enable per-sample debug logs in <out-dir>/logs/")
    parser.add_argument("--resume", action="store_true",
                        help="Skip samples that already have a result (no error)")
    parser.add_argument("--seed", type=int, default=None,
                        help="Random seed for sample selection (default: random)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show agent INFO logs")
    parser.add_argument("--no-colour", action="store_true",
                        help="Disable terminal colour codes")

    args = parser.parse_args()

    # Disable colour if requested or if stdout is not a tty.
    if args.no_colour or not sys.stdout.isatty():
        global _RESET, _RED, _GREEN, _YELLOW, _CYAN, _BOLD, _DIM
        _RESET = _RED = _GREEN = _YELLOW = _CYAN = _BOLD = _DIM = ""

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(name)s  %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )
    if not args.verbose:
        for noisy in ("httpx", "httpcore", "anthropic", "langchain", "langgraph",
                      "agent", "agent.joern"):
            logging.getLogger(noisy).setLevel(logging.WARNING)

    if args.max_iter is not None:
        os.environ["AGENT_MAX_ITER"] = str(args.max_iter)

    # On SIGTERM (e.g. from the `timeout` command) Python does NOT run atexit
    # handlers — register one explicitly so Joern servers are always cleaned up.
    import signal as _signal
    def _sigterm_handler(signum, frame):
        from tools.joern import _atexit_kill_all_servers
        _atexit_kill_all_servers()
        sys.exit(128 + signum)
    _signal.signal(_signal.SIGTERM, _sigterm_handler)

    if not os.environ.get("ANTHROPIC_API_KEY") and not args.summary and not args.rescore:
        sys.exit("error: ANTHROPIC_API_KEY environment variable not set")

    # --summary: aggregate existing results only (using saved scores).
    if args.summary:
        existing = load_existing(args.out_dir)
        if not existing:
            sys.exit(f"no results found in {args.out_dir}")
        records = list(existing.values())
        print_summary_table(records)
        return

    # --rescore: re-run scoring.py against all cached results and display summary.
    # Does not re-run the agent or touch the saved JSON files.
    if args.rescore:
        from models import AnalysisResult
        from scoring import score_result

        existing = load_existing(args.out_dir)
        if not existing:
            sys.exit(f"no results found in {args.out_dir}")

        corpus_dir = args.corpus_dir
        rescored: List[Dict[str, Any]] = []
        skipped = 0

        for name, rec in sorted(existing.items()):
            if rec.get("error") or not rec.get("result"):
                skipped += 1
                continue
            sample_dir = corpus_dir / name
            if not (sample_dir / "ground_truth.json").exists():
                skipped += 1
                continue
            try:
                result = AnalysisResult(**rec["result"])
                score = score_result(result, sample_dir)
                score["predicted_verdict"] = result.verdict.value
                score["duration_s"] = rec.get("duration_s")
                gt = json.loads((sample_dir / "ground_truth.json").read_text())
                score["expected_verdict"] = gt.get("verified", "?")
                rec = dict(rec)   # shallow copy — don't mutate cached dict
                rec["score"] = score
            except Exception as exc:
                log.warning("rescore failed for %s: %s", name, exc)
                skipped += 1
                continue
            rescored.append(rec)
            print_progress(rec)

        if skipped:
            print(f"\n({skipped} records skipped — errors or missing ground truth)")
        print_summary_table(rescored)
        return

    # Discover and select samples.
    all_samples = discover_samples(args.corpus_dir)
    if not all_samples:
        sys.exit(f"no samples with ground_truth.json found in {args.corpus_dir}")

    samples = select_samples(
        all_samples,
        run_all=args.all,
        n=args.n,
        ids=args.sample,
        filters=args.filter or [],
        seed=args.seed,
    )

    if not samples:
        sys.exit("no samples selected (check --filter / --sample arguments)")

    # Optionally skip already-completed samples.
    if args.resume:
        existing = load_existing(args.out_dir)
        before = len(samples)
        samples = [
            s for s in samples
            if not (s.name in existing and existing[s.name].get("error") is None)
        ]
        skipped = before - len(samples)
        if skipped:
            print(f"Resuming: skipping {skipped} already-completed samples.")

    if not samples:
        print("All selected samples already complete. Use --summary to view results.")
        return

    # Kill any Joern server processes left over from previous crashed runs.
    # Must happen before starting new workers so they don't fight for ports.
    from tools import kill_stale_joern_servers
    killed = kill_stale_joern_servers()
    if killed:
        print(f"Cleaned up {killed} stale Joern server process(es) from previous runs.")

    # Resolve log directory.
    log_dir: Optional[Path] = None
    if args.log_dir:
        log_dir = args.log_dir
    elif args.logs:
        log_dir = args.out_dir / "logs"
    if log_dir:
        log_dir.mkdir(parents=True, exist_ok=True)
        print(f"Per-sample debug logs → {log_dir}/")

    print(f"\nRunning {len(samples)} samples  (workers={args.workers}  timeout={args.timeout}s)\n")

    completed_records: List[Dict[str, Any]] = []

    def _run(sample_dir: Path) -> Dict[str, Any]:
        return run_sample(sample_dir, timeout=args.timeout, log_dir=log_dir)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(_run, s): s for s in samples}
        for future in as_completed(futures):
            sample_dir = futures[future]
            try:
                # Enforce the per-sample wall-clock timeout here.
                # The underlying thread may keep running (threads can't be
                # killed), but we stop waiting and record a timeout error.
                record = future.result(timeout=args.timeout)
            except TimeoutError:
                record = {
                    "sample":     sample_dir.name,
                    "binary":     str(find_binary(sample_dir)) if sample_dir else None,
                    "duration_s": args.timeout,
                    "error":      f"TimeoutError: exceeded {args.timeout}s wall-clock limit",
                    "result":     None,
                    "score":      None,
                }
            except Exception as exc:
                record = {
                    "sample":     sample_dir.name,
                    "binary":     None,
                    "duration_s": None,
                    "error":      f"{type(exc).__name__}: {exc}",
                    "result":     None,
                    "score":      None,
                }
            save_record(record, args.out_dir)
            completed_records.append(record)
            print_progress(record)

    # Also include any pre-existing records if resuming.
    if args.resume:
        existing = load_existing(args.out_dir)
        all_records = list(existing.values())
    else:
        all_records = completed_records

    print_summary_table(all_records)


if __name__ == "__main__":
    main()
