# Configuration-Aware Vulnerability Analysis Agent — One-Page Summary

A proof-of-concept tool that finds potential command injection vulnerabilities in compiled C binaries and (1) validates whether the vulnerability is truly exploitable, and (2) enriches the report with the runtime configuration preconditions that gate it. Many scanners flag issues without context — this agent determines *under what configuration* a vulnerability is actually reachable.

## Verdicts

The agent returns **Exploitable** (with preconditions), **NotExploitable**, or **Inconclusive** for each binary.

## Causal Link Model

Exploitability is modeled as four independent facts that must all hold:

1. **config_to_variable** — A configuration option (CLI flag, config-file key, or prior runtime operation) sets a gate variable to an enabling value.
2. **variable_to_gate** — That gate variable is read in a branch condition guarding the dangerous sink.
3. **gate_to_sink** — When the branch is satisfied, execution reaches the sink with no further unconditional block.
4. **input_to_argument** — Attacker-supplied data flows into the sink argument without full sanitization.

If any link fails, the vulnerability is not exploitable under that configuration.

## Architecture

Built on **LangGraph** + **Claude** (claude-sonnet-4-6). Two-level graph:

- **Main graph:** `setup` → `enumerate_sinks` → fan-out per sink via `Send` → `aggregate_results`
- **Per-sink subgraph:** `check_input_reach` → `trace_and_classify_gate` → `trace_input_path` → `assess_sanitization` → `synthesize_preconditions` ⇄ `causal_verify` (retry loop, max 3 attempts)

Tools: **Joern** (CPG queries via persistent HTTP server), **objdump** (disassembly, tried first for speed), **angr** (symbolic execution, last resort). Assembly-first strategy minimizes JVM overhead.

## Configuration Taxonomy

| Type | Example |
|------|---------|
| `cli_flag` | `--exec-mode` sets a global enabling the vulnerable path |
| `config_file` | `exec_mode = 1` in a key=value file parsed at startup |
| `runtime_state` | A prior request (e.g. `/exec/init`) sets a global flag |

Preconditions use `sense: present` (option must be active) or `absent` (e.g. a sanitization flag must be missing for exploitation).

## Evaluation and Corpus

Generated ~155 synthetic sample C/C++ HTTP servers based upon ~10 open source http servers using claude. Samples varied across three axes:

- **C-axis (config complexity):** C1 (single CLI flag) → C2 (config file) → C3 (config file + runtime state)
- **I-axis (input flow):** I1 (direct) → I2 (buffered) → I3 (struct dispatch)
- **S-axis (sanitization):** S1 (none) → S2 (bypassable filter) → S3 (config-gated sanitization)

All 45 axis combinations are covered. Each sample includes a patch, build script, PoC exploit, and ground-truth metadata.

## Key Design Decisions

- **Parallel per-sink analysis** via LangGraph `Send` with an add-reducer for thread-safe result accumulation.
- **Synthesis/verify retry loop** separates hypothesis formation from testing, giving the LLM fresh context on each retry.
- **High-recall reachability** — `check_input_reach` defaults to reachable when uncertain (false positives are cheap; false negatives are terminal).
- **Domain-agnostic reasoning** — nodes reason about mechanisms (`cli_flag`, `config_file`, `runtime_sequence`), not corpus labels. Retargeting to non-HTTP binaries requires only swapping the input-source function list.
