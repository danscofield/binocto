# Configuration Aware Vulnerability Analysis Agent — Design Document

This tool is a proof of concept that takes a static analyzer hit or a vulnerability report and: (1) validates the vulnerability is accurate; and (2) enriches the report to supply additional runtime configuration that may gate the vulnerability. The problem the tool aims to solve is that many scanners and CVE reports are severly lacking in detail, and context is really important to understanding software vulnerabilities. The fact that a memory corruption issue (or command injection vulnerability, etc.) exists in a binary doesn't mean its actually vulnerable in all situations. Some people refer to this as the 'runtime' build of materials, but even that concept is generally less specific than what we're building here. Scanners flagging issues this way creates challenges for AppSec engineers or Vulnerability Management teams when it comes to bug triage, sometimes leading to availability issues caused by unnecessary patching. My tool tries to go a step further by understanding software configuration. 

This problem is challenging because, from a program analysis perspective, configuration is just another form of input. There is no semantic distinction between a value read from a config file, a command-line flag, or a byte received over a network socket. They are all external data that influence control flow. But in practice, this equivalence is exactly what makes vulnerability analysis of real-world software so intractable. A typical server binary might read hundreds of configuration parameters at startup, each of which can enable or disable features, alter parsing behavior, toggle security checks, or change the topology of the call graph that handles subsequent inputs. The state space that a traditional analyses had to consider were therefore intractable.

The current prototype is designed around command injections (but could be adapted to whatever type of vulnerability). It was tested on a corpus of ~155 synthetic vulnerabilities (see the corpus design and evaluation sections)

## Overview

Our agent analyses compiled C binaries for exploitable command-injection
vulnerabilities — cases where externally-supplied, attacker-controlled input
reaches a dangerous sink (`system`, `execve`, `popen`, etc.) under particular
runtime configuration conditions.

Given a binary, the agent returns one of three verdicts:

| Verdict | Meaning |
|---|---|
| **Exploitable** | All four causal links confirmed; preconditions listed |
| **NotExploitable** | At least one causal link is definitively refuted |
| **Inconclusive** | Insufficient evidence to confirm or refute after max attempts |

When the verdict is Exploitable, the agent also returns the set of
**preconditions** — configuration flags, config-file keys, or prior runtime
operations — that an attacker must satisfy for the vulnerability to be reachable.

The analysis is domain-agnostic: it works on any binary that accepts external
input and calls dangerous functions. The current corpus consists of HTTP server
binaries, so the tool prompts name HTTP-specific source functions (`recv`,
`mg_http_get_var`, etc.) — but nothing in the graph structure or reasoning 
pipeline requires this. The same approach applies to FTP servers, SMTP daemons,
CLI tools reading from stdin, or any other program that processes 
externally-controlled data.

---

## Causal Link Model

Exploitability is not a single yes/no property — we model it as a chain of
4 independent facts that must all hold simultaneously. The agent calls these
**causal links**. Each link is a verifiable claim about the binary; if any
one fails, the vulnerability is not exploitable under that configuration.

```
  configuration option
         │
         │  config_to_variable
         ▼
    gate variable
         │
         │  variable_to_gate
         ▼
    branch condition  ──── gate_to_sink ────►  dangerous sink call
                                                      ▲
  externally-supplied                                 │
       input  ──────────── input_to_argument ─────────┘
```

| Link | Claim |
|---|---|
| **config_to_variable** | The configuration option (flag, file key, or prior runtime operation) sets a specific memory location — the *gate variable* — to a value that enables the vulnerable code path. |
| **variable_to_gate** | That gate variable is read in a branch condition that determines whether execution proceeds toward the sink. |
| **gate_to_sink** | When the branch condition is satisfied, execution reaches the dangerous sink call — i.e. there is no second gate or unconditional return between the branch and the call. |
| **input_to_argument** | The data supplied by the external attacker flows into the argument passed to the sink, without being fully neutralised by sanitization. |

All four links are necessary because each rules out a different class of false
positive:
- Without **config_to_variable**, the "precondition" might be a variable that
  nothing in the binary ever assigns based on that option.
- Without **variable_to_gate**, the variable might be written by the option but
  never actually tested before the sink.
- Without **gate_to_sink**, the branch might guard something else; a second
  unconditional check could still block the sink.
- Without **input_to_argument**, the sink might be reached but fed only
  hard-coded data, not attacker-controlled input.

---

## Architecture

The agent is built on **LangGraph** with **Claude** (claude-sonnet-4-6) as the
reasoning engine. The graph has two levels:

1. **Main graph** — orchestrates setup, sink discovery, parallel per-sink
   analysis, and result aggregation.
2. **Per-sink subgraph** — a sequential pipeline of analysis stages run
   independently for each discovered sink, with a synthesis/verify retry loop.

Tool calls use **Joern** (Code Property Graph queries via persistent HTTP
server) and **objdump** (disassembly) as the primary analysis primitives.
**angr** symbolic execution is available as a last resort for non-obvious
comparison values.

---

## Graph Definition

### Main Graph (`GraphState`)

```
START
  │
  ▼
setup                      Build Joern CPG; start persistent Joern server
  │
  ▼
enumerate_sinks            LLM agent: find all dangerous call sites
  │
  ├─ [no sinks found] ──────────────────────────────────────┐
  │                                                          │
  ├─ Send(sink_1) ──► [per-sink subgraph] ──────────────────┤
  ├─ Send(sink_2) ──► [per-sink subgraph] ──────────────────┤  (parallel)
  └─ Send(sink_N) ──► [per-sink subgraph] ──────────────────┤
                                                             │
                                                             ▼
                                                    aggregate_results
                                                             │
                                                           END
```

**State (`GraphState`):**

| Field | Type | Description |
|---|---|---|
| `binary` | `str` | Absolute path to the binary under analysis |
| `joern_cpg` | `str` | Path to the Joern CPG `.bin` file |
| `sink_list` | `List[Sink]` | Dangerous call sites found by enumerate_sinks |
| `results` | `List[SinkResult]` | Accumulated per-sink results (add reducer — parallel-safe) |
| `analysis_result` | `Optional[AnalysisResult]` | Final rolled-up result, written by aggregate_results |

---

### Per-Sink Subgraph (`SinkState`)

Compiled separately and registered as the `check_input_reach` node in the main
graph. Dispatched once per sink via `Send`, so N sinks run in parallel.

```
START
  │
  ▼
check_input_reach          Can externally-supplied input reach the sink argument?
  │
  ├─ [not reachable] ──► record_sink_not_reachable ──► END
  │
  ▼ [reachable]
trace_and_classify_gate    Identify gate conditions AND their source mechanism
  │
  ▼
trace_input_path           Characterise the external entry point and input delivery
  │
  ▼
assess_sanitization        Find any sanitization on the input path
  │
  ▼
synthesize_preconditions   Build ConfigurationOption hypothesis + causal chain
  │                        (re-entered on revision with failure feedback)
  ▼
causal_verify              Confirm all four causal links via assembly + CPG
  │
  ├─ [Exploitable]     ──► record_sink_success ──► END
  ├─ [NotExploitable]  ──► record_sink_success ──► END
  │
  ├─ [Inconclusive, attempts < MAX] ──► synthesize_preconditions  (retry loop)
  │
  └─ [Inconclusive, attempts >= MAX] ──► record_sink_inconclusive ──► END
```

`MAX_VERIFY_ATTEMPTS = 3`

**State (`SinkState`):**

| Field | Type | Populated by |
|---|---|---|
| `binary` | `str` | Propagated from GraphState |
| `joern_cpg` | `str` | Propagated from GraphState |
| `sink` | `Sink` | Dispatch (from sink_list) |
| `input_reachable` | `Optional[bool]` | check_input_reach |
| `gate_source` | `Optional[str]` | trace_and_classify_gate |
| `gate_conditions` | `list` | trace_and_classify_gate |
| `input_path` | `Optional[dict]` | trace_input_path |
| `sanitization` | `Optional[dict]` | assess_sanitization |
| `causal_chain` | `Optional[dict]` | synthesize_preconditions |
| `precondition_hypothesis` | `List[ConfigurationOption]` | synthesize_preconditions |
| `verify_attempts` | `int` | causal_verify |
| `verify_failure_reason` | `Optional[str]` | causal_verify |
| `results` | `List[SinkResult]` | record_sink_* (add reducer) |

---

## Node Descriptions

### `setup`
**Type:** Deterministic (no LLM)

Builds the Joern CPG for the binary using `joern-parse --language ghidra`.
CPGs are cached under `$JOERN_CACHE_DIR/<sha256(binary)[:20]>/cpg.bin`.

Starts a persistent Joern HTTP server for the CPG so subsequent queries avoid
JVM startup overhead (~10s per cold query). The server is killed in
`aggregate_results` and also via an atexit handler for crash safety.

Writes: `joern_cpg`

---

### `enumerate_sinks`
**Type:** LLM agent (ReAct loop)

Finds all call sites for the dangerous function set:
`system, execve, execvp, execvpe, execl, execle, execlp, popen`

**Tools available:**
- `joern_find_dangerous_calls(function_name)` — queries the CPG for call sites
- `joern_raw(scala_body)` — arbitrary CPGql for edge cases

**Output:** JSON array of Sink objects:
```json
[{"addr": "0x401234", "function": "system", "arg_index": 0, "caller": "handle_exec"}]
```

Writes: `sink_list`

On max-iteration or parse failure: returns empty list (graceful degradation).

---

### `check_input_reach`
**Type:** LLM agent (fast-fail)

Determines whether attacker-controlled external input can flow to the sink
argument. Defaults to `reachable=true` when uncertain (high recall over
precision — false positives are resolved later; false negatives are terminal).

The node is given a list of known input-source functions appropriate to the
binary type (for the HTTP corpus: `recv`, `read`, `getenv`, `mg_http_get_var`,
etc.; for other domains these would be replaced accordingly).

**Tools available:**
- `asm_function(name)` — objdump disassembly (always try first, no JVM)
- `joern_forward_taint(source_fn)` — taint from input sources to sink
- `joern_decompile(name)` — function call sequence from CPG
- `joern_get_callers(name)` — call graph traversal
- `joern_raw(scala_body)`

**Output:** `{"reachable": bool, "confidence": str, "reason": str}`

Routes to: `trace_and_classify_gate` (reachable) or `record_sink_not_reachable`

---

### `trace_and_classify_gate`
**Type:** LLM agent (combined two-step pass)

Identifies gate conditions controlling whether the sink executes, and
simultaneously classifies the source mechanism. Fusing these into one pass
saves one full agentic loop compared to running them separately.

**Gate source taxonomy:**

| Source | Description |
|---|---|
| `cli_flag` | Variable set by argv parsing; e.g. `--exec-mode` |
| `config_file` | Variable set by reading a file at startup; e.g. `exec_mode = 1` |
| `runtime_sequence` | Variable set by a prior external request or operation at runtime; e.g. a setup call that unlocks a code path |

The `runtime_sequence` category is deliberately general: in an HTTP corpus it
maps to an init endpoint; in other domains it could be a protocol handshake, a
prior file write, a database row, etc.

**Tools available:**
- `asm_function(name)` — always first; shows compare/branch patterns
- `joern_get_variable_defs(name)` — cross-function variable assignment tracing
- `joern_trace_condition(addr)` — dominating conditions at an address
- `joern_get_callers(name)` — call chain traversal
- `binary_strings(min_length)` — exact flag/key/route strings from the binary
- `joern_raw(scala_body)`

Writes: `gate_source`, `gate_conditions`

---

### `trace_input_path`
**Type:** LLM agent

Characterises the external entry point for attacker-controlled data: which
function receives it, what parameter carries the payload, and how it is
delivered to the sink (directly, via a buffer, via a struct field, etc.).

In the HTTP corpus this means identifying the route and query parameter. In
other domains it would mean identifying the socket read, parsed field, or
command-line argument. The output schema uses generic terms (`entry_point`,
`param`, `delivery`) with HTTP-specific fields populated for the current corpus.

**Tools available:**
- `asm_function(name)`
- `joern_forward_taint(source_fn)`
- `joern_decompile(name)`
- `joern_get_callers(name)`
- `joern_raw(scala_body)`

**Output:**
```json
{
  "entry_point": "/exec",
  "param": "cmd",
  "delivery": "direct",
  "handler_fn": "handle_exec",
  "taint_confirmed": true
}
```

Writes: `input_path`

---

### `assess_sanitization`
**Type:** LLM agent

Looks for character-filter functions (`strpbrk`, `strchr`, `strcspn` on shell
metacharacters) or allowlist comparisons between the external input and the
sink.

Classifies sanitization into three cases:
1. **Always active** → exploitation blocked (NotExploitable)
2. **Bypassable** → notes the bypass method
3. **Config-gated (S3 pattern)** → the sanitization runs only when a flag is
   set; that flag must be *absent* for exploitation → adds an `absent`-sense
   precondition

**Tools available:**
- `asm_function(name)`
- `joern_function_calls(name)` — sorted call sequence
- `joern_trace_condition(addr)`
- `joern_decompile(name)`
- `joern_raw(scala_body)`

Writes: `sanitization`

---

### `synthesize_preconditions`
**Type:** LLM agent (no tools — pure reasoning)

Takes the findings from the four preceding analysis nodes — gate variable
identity, gate source mechanism, input path, sanitization — and assembles
them into a typed `ConfigurationOption` list and a `causal_chain` narrative.

The `causal_chain` explicitly maps each of the four causal links to the
evidence gathered, giving `causal_verify` a concrete starting point rather
than asking it to re-derive everything from scratch.

On retry passes (after a `causal_verify` failure), receives the failed
hypothesis and the specific broken link as feedback, then revises the
preconditions and chain description accordingly.

**Key rule — enabling vs. restricting gates:**
- *Enabling gate* (include): without the option, execution never reaches the
  sink. The option is a necessary condition.
- *Restricting gate* (omit): the option constrains *who* can reach the sink,
  but the sink is reachable regardless. (Example: `--auth` adds authentication
  but does not gate the exec code path itself; the vulnerability exists with
  or without it.)

**`ConfigurationOption` schema:**

```python
class ConfigurationOption(BaseModel):
    configuration_type:      "flag" | "file" | "runtime_state"
    configuration_parameter: str    # "--exec-mode", "exec_mode", "/exec/init"
    configuration_value:     Optional[str]  # None for flags; "1", "s3cr3t" for others
    sense:                   "present" | "absent"
```

`sense: "absent"` is used for sanitization options: a sanitization check that
blocks exploitation when active means the check's enabling flag must be *absent*
for the vulnerability to be reachable.

`runtime_state` covers any precondition established by a prior runtime
operation — in the HTTP corpus this is typically a call to an init endpoint,
but the type is not HTTP-specific.

Writes: `precondition_hypothesis`, `causal_chain`

---

### `causal_verify`
**Type:** LLM agent (the critical verification step)

Confirms or refutes each of the four causal links (see *Causal Link Model*
above) against assembly and CPG evidence. The node asks a concrete question
for each link:

| Link | Concrete question |
|---|---|
| `config_to_variable` | Does the configuration option write the gate variable to the enabling value? |
| `variable_to_gate` | Is that variable read in the branch that guards the sink? |
| `gate_to_sink` | When the branch is satisfied, does execution reach the sink with no further unconditional block? |
| `input_to_argument` | Does attacker-supplied data reach the sink argument without being fully neutralised? |

**Tools available:**
- `asm_function(name)` — primary; sufficient for links 2, 3, often 4
- `joern_get_variable_defs(name)` — link 1: cross-function assignment tracing
- `joern_forward_taint(source_fn)` — link 4: when entry point and sink are far apart
- `joern_get_callers(name)` — call chain traversal
- `binary_strings(min_length)` — confirm exact flag/key/route literals exist
- `angr_solve_value(config_fn, gate_addr, flag_args)` — symbolic execution for
  non-obvious comparison values (magic integers, computed checks)
- `joern_raw(scala_body)`

**Routing on verdict:**
- `Exploitable` → `record_sink_success` (writes result, exits subgraph)
- `NotExploitable` → `record_sink_success` (writes result, exits subgraph)
- `Inconclusive` with attempts < MAX → `synthesize_preconditions` (retry)
- `Inconclusive` with attempts ≥ MAX → `record_sink_inconclusive`

Reads: `precondition_hypothesis`, `causal_chain`
Writes: `verify_attempts`, `verify_failure_reason`, `results` (on terminal verdict)

---

### `aggregate_results`
**Type:** Deterministic (no LLM)

Stops the Joern server, then collapses all per-sink `SinkResult` records into
a single binary-level `AnalysisResult`.

**Verdict roll-up rules:**
1. Any sink Exploitable → binary verdict Exploitable (canonical = sink with
   fewest preconditions)
2. All sinks NotExploitable → binary verdict NotExploitable
3. Any Inconclusive (rest NotExploitable) → binary verdict Inconclusive
4. No sinks found → Inconclusive

Writes: `analysis_result`

---

## Data Models

```
AnalysisResult
  binary:         str
  verdict:        Verdict          # Exploitable | NotExploitable | Inconclusive
  preconditions:  List[ConfigurationOption]
  sink_results:   List[SinkResult]

SinkResult
  sink:           Sink
  verdict:        Verdict
  preconditions:  List[ConfigurationOption]
  attempts:       int
  evidence:       dict             # causal links, assembly offsets, etc.

Sink
  addr:           int              # virtual address (decimal)
  function:       str              # "system", "execve", etc.
  arg_index:      int              # which argument carries tainted data
  caller:         str              # containing function name

ConfigurationOption
  configuration_type:      "flag" | "file" | "runtime_state"
  configuration_parameter: str
  configuration_value:     Optional[str]
  sense:                   "present" | "absent"
```

---

## Tool Infrastructure

### Joern (Code Property Graph)

**Server lifecycle:**
- One JVM per binary, started in `setup`, killed in `aggregate_results`
- `preexec_fn=os.setsid` puts the JVM in its own process group; `os.killpg()`
  kills the shell wrapper and JVM child together
- `atexit` handler and SIGTERM handler ensure cleanup on crash/timeout
- `kill_stale_joern_servers()` kills orphaned JVMs at eval startup

**Query execution (server mode):**
- Queries are submitted via `POST /query → UUID → poll GET /result/<uuid>`
- The server returns `success:false, err:"No result (yet?)"` while processing
  (not HTTP 202); the polling loop handles this correctly
- `println()` output is redirected to a per-query temp file via a
  `java.io.PrintWriter` injected before the query body; the file is read after
  the query completes
- Each query body is wrapped in `try/catch/finally` so Scala exceptions are
  captured to the file rather than silently lost
- Resilience: `c.method.name` accessed via `scala.util.Try(...)` to handle
  null graph references in Ghidra-frontend CPGs

**Caching:**
- SHA-256 of query body → `q_<hash>.txt` alongside `cpg.bin`
- Empty and `JOERN_ERROR:` results are not cached (may be transient)
- Stale error/empty entries are invalidated on read

**CPG traversal types (valid in Ghidra-frontend CPGs):**

| Valid | Invalid (use instead) |
|---|---|
| `cpg.call` | `cpg.string` → use `cpg.literal` |
| `cpg.method` | `cpg.variable` → use `cpg.local` or `cpg.call` args |
| `cpg.literal` | `cpg.identifier` → empty in Ghidra CPGs |
| `cpg.parameter` | |
| `cpg.local` | |

### Binary Tools

| Tool | Implementation | Purpose |
|---|---|---|
| `objdump` | subprocess | Disassemble a function by name |
| `strings` | subprocess | Extract printable strings |
| `binary_info` | subprocess | ELF metadata (arch, bits, stripped) |
| `read_bytes` | direct read | Raw hex bytes at an address |

### angr (Symbolic Execution)

Used only by `causal_verify` via `angr_solve_value`. Invoked when assembly
shows a comparison against a non-obvious value (magic integer, computed check)
that cannot be read as a plain string literal. Timeout: 90 seconds.

### Execution Harness

`subprocess_harness` runs the binary under test with a specified set of
arguments and setup files, sends a sequence of requests, and checks for a
marker (file existence or response content). The current implementation
sends HTTP requests, matching the corpus; a different harness would be needed
for non-HTTP binaries (e.g. piping stdin, sending raw socket data).

---

## Agentic Loop

Each node that uses an LLM runs a standard **ReAct** loop via
`run_analysis_agent()`:

```
LLM ──► tool calls ──► tool results ──► LLM ──► ... ──► final text answer
```

The loop runs for up to `AGENT_MAX_ITER` iterations (default 100, configurable
via `--max-iter` or `$AGENT_MAX_ITER`). On exhaustion, a `RuntimeError` is
raised; most nodes catch this and return a safe default.

The LLM is Claude (claude-sonnet-4-6, or `$CLAUDE_MODEL` override) with
`temperature=0` for determinism.

---

## Corpus Evaluation

`eval.py` runs the agent against the full corpus or a random sample in
parallel, scores results against ground-truth JSON files, and prints a summary
table.

```
python3 eval.py -n 20 --seed 42 --workers 4 --timeout 600 --logs
```

**Scoring axes** (corpus-specific labels derived from the precondition types
the agent produces):

| Axis | What it measures |
|---|---|
| C-axis | Configuration complexity: C1 (cli flag) → C2 (config file) → C3 (runtime sequence) |
| S-axis | Sanitization complexity: S1 (none) → S2 (bypassable) → S3 (config-gated) |
| I-axis | Input complexity: I1 (direct) → I2 (one hop) → I3 (multi-hop) |

**Per-sample debug logs** are written to `eval_results/logs/<sample>.log` when
`--logs` is set. Logs capture all DEBUG-level output from the agent and Joern
tooling for that sample's thread, making post-hoc failure diagnosis possible
without re-running.

---

## Key Design Decisions

**Parallel sink analysis via `Send`.**
LangGraph's `Send` API fans out one subgraph invocation per sink. The
`results` field uses `operator.add` as its reducer so parallel branches append
without clobbering each other.

**Synthesis/verify retry loop.**
Rather than running one long reasoning session, the agent separates hypothesis
formation (`synthesize_preconditions`) from hypothesis testing (`causal_verify`)
and loops up to `MAX_VERIFY_ATTEMPTS=3` times with structured failure feedback.
This gives the LLM a fresh context each iteration and avoids compounding errors.

**Assembly-first tool strategy.**
All nodes instruct the LLM to call `asm_function` (objdump) first. It has no
JVM startup cost, is cached, and covers the common case (gate logic is
typically visible in a single function's assembly). Joern is the fallback for
cross-function concerns.

**Domain-agnostic reasoning, corpus-specific tool configuration.**
Nodes reason about mechanisms (`cli_flag`, `config_file`, `runtime_sequence`)
not corpus labels (`C1`, `C2`, `C3`). The set of input-source functions passed
to `check_input_reach` and `causal_verify` is the main corpus-specific
parameter — swapping it is sufficient to retarget the agent to a different
class of binary. The scoring layer derives axis labels from mechanisms
independently.

**High-recall reachability check.**
`check_input_reach` defaults to `reachable=true` when uncertain. A false
positive costs one extra analysis pipeline run; a false negative silently misses
a real vulnerability. The full pipeline is the right place to rule out sinks.

# Evaluation Results

## Corpus Design

We built a corpus of C/C++ web servers patched with synthetic, config-gated command-injection
vulnerabilities to test the agentic analysis across three axes simultaneously. These axes
independently vary how hard the answer is to compute the answer statically.

---

### Directory layout

```
corpus/
  CORPUS.md               ← this file
  darkhttpd/              ← unmodified server source (git clone)
  tinyhttpd/
  tiny-web-server/
  mongoose/
  mini_httpd/
  civetweb/
  merecat/
  kore/
  lighttpd/
  lwan/
  h2o/
  onion/
  ulfius/
  libwebsockets/
  seasocks/
  samples/
    NNN_SERVER_CxIySz/    ← one directory per sample
      PROVENANCE          ← structured metadata
      patch.diff          ← unified diff vs unmodified source
      build.sh            ← compiles binary into this directory
      PoC.sh              ← end-to-end exploit + negative gate check
      <binary>            ← pre-built patched binary
```

Sample numbers are assigned sequentially and are stable; they do not encode meaning
beyond ordering.

---

### Three-Axis Taxonomy

#### C axis — Config Gate Complexity

How many static-analysis hops lie between the source of the flag value and the guard
that protects the sink?

| Label | Name | Mechanism | Tracing difficulty |
|-------|------|-----------|-------------------|
| **C1** | Single CLI flag | `static int exec_mode = 0;` set by `--exec-mode` argv check; one boolean guard one or two lines above `system()` | Trivial — argv → global → guard, 1 hop |
| **C1b** | Multi-flag CLI | Two CLI flags stored in a `struct exec_config { int enabled; int logging; }`; guard checks both fields | Low — two argv chains into a struct, still direct |
| **C1c** | Multi-flag CLI + utility fn | Three CLI flags + a `static int exec_is_ready(void)` indirection; guard calls the function | Low-moderate — three argv chains, one function call indirection |
| **C2** | Config file | One or two settings parsed from a key=value config file via `fopen`/`fgets`/`sscanf` into a struct; guard checks struct fields | Moderate — requires modelling file I/O data flow across function boundaries |
| **C3** | Config file + runtime state | Config file populates a struct **and** a separate runtime condition must be satisfied (e.g. a prior `/exec/init` HTTP call sets `exec_initialized`); guard checks both | Hard — requires modelling both file I/O and inter-request state |

**C1b** and **C1c** are intermediate labels for samples originally produced under the
C2/C3 slots before the config-file distinction was established.  They are valid test
cases but stress the same CLI-tracing code path as C1; they are not useful for testing
config-file data-flow analysis.

#### I axis — Input Flow

How many transforms lie between the raw HTTP query parameter and the `system()` call?

| Label | Name | Mechanism |
|-------|------|-----------|
| **I1** | Direct | `cmd` pointer from URL query string passed verbatim to `system(cmd)` |
| **I2** | Buffered | `snprintf(shell_cmd, sizeof(shell_cmd), "sh -c '%s' 2>/dev/null", cmd); system(shell_cmd);` — one intermediate buffer |
| **I3** | Struct dispatch | `exec_args_t args = {.cmd = cmd, .flags = 0}; dispatch_exec(&args);` where `dispatch_exec` calls `system(args->cmd)` — pointer through a struct and a helper function |

#### S axis — Sanitization

What filtering (if any) is applied to `cmd` before `system()`?

| Label | Name | Mechanism | Bypass |
|-------|------|-----------|--------|
| **S1** | None | No check | N/A — no sanitization to bypass |
| **S2** | Bypassable filter | `if (strchr(cmd, '\|') != NULL) { reject 403; }` — blocks pipe character | Use `;` or bare `>` redirection instead |
| **S3** | Config-gated sanitization | `static int strict_exec = 0;` set by `--strict-exec`; `if (strict_exec && strpbrk(cmd, "\|;&\`$") != NULL) { reject; }` — full metachar check only when flag is present | Omit `--strict-exec` when starting server; sanitization is never activated |

---

### Axis combinations and corpus coverage

All 5 × 3 × 3 = 45 axis combinations are represented (some more than once):

```
C1   × I{1,2,3} × S{1,2,3}   — 9 combos, ~45 samples (001–116 range)
C1b  × I{1,2,3} × S{1,2,3}   — 9 combos, ~36 samples (001–116 range)
C1c  × I{1,2,3} × S{1,2,3}   — 9 combos, ~35 samples (001–116 range)
C2   × I{1,2,3} × S{1,2,3}   — 9 combos, ~36 samples (117–152 range)
C3   × I{1,2,3} × S{1,2,3}   — 9 combos, ~36 samples (153–188 range)
```

---

### Servers

| Server | Language | Build | Notes |
|--------|----------|-------|-------|
| darkhttpd | C | `gcc` | Single-file; existing `--port` CLI |
| tinyhttpd | C | `gcc -lpthread` | Single-file; port hardcoded — patch adds `--port` |
| tiny-web-server | C | `gcc` | Single-file; fork-per-connection |
| mongoose | C | `gcc` (amalgam) | Library; corpus adds `server.c` base file |
| mini_httpd | C | `gcc -lcrypt -w` | Single-file ~3800 lines; link `match.c tdate_parse.c` |
| civetweb | C | `cmake` | Library + standalone; patch targets `src/main.c` |
| merecat | C | `make` (autoconf) | Uses libconfuse for config; patch targets `src/libhttpd.c` + `src/merecat.c` |
| kore | C | `make` | Custom build; seccomp disabled in patch for child exec |
| lighttpd | C | `cmake` | Full-featured; config-file server; patch targets `src/response.c` + `src/server.c` |
| lwan | C | `cmake` | Event-driven; patch targets `src/bin/lwan/main.c` |
| h2o | C | `cmake` | HTTP/2 capable; YAML config; patch targets `src/main.c` |
| onion | C | `cmake` | Library; corpus adds `server.c` base file |
| ulfius | C | `cmake` | REST framework; corpus adds `server.c` base file |
| libwebsockets | C | `cmake` | WebSocket + HTTP; corpus adds `server.c` base file |
| seasocks | C++ | `cmake` | C++ library; corpus adds `server.cpp` base file |

---

### Sample artifacts

Every sample directory contains exactly these files:

| File | Description |
|------|-------------|
| `PROVENANCE` | Structured text: PACKAGE, COMMIT, SOURCE, AXES, DESCRIPTION, CONFIG_GATE, INPUT_FLOW, SANITIZATION, SINK, CHANGED FILES, EXPLOIT, NOTES |
| `patch.diff` | Unified diff (`diff -u --label "a/file" --label "b/file"`) applied with `patch -p1` |
| `build.sh` | Copies unmodified source to a temp dir, applies patch, compiles binary into the sample directory |
| `PoC.sh` | Starts patched binary with gate enabled, sends exploit, verifies RCE via file write, then runs negative control (gate disabled → 404) |
| `<binary>` | Pre-built patched binary; `build.sh` regenerates it deterministically |

---

### C2 config file format

C2 patches add a minimal key=value config file reader (or hook into the server's
existing config parser).  The config file is passed via `--config /path/to/file`.

Example config that enables the exec endpoint:

```ini
exec_mode = 1
exec_logging = 1
```

The gate check reads both fields from the file; both must be `1` for `/exec` to be
reachable.  Joern must model `fopen` → `fgets` → `sscanf` data flow to determine
whether `exec_cfg.enabled` can be non-zero.

---

### C3 config file + runtime state

C3 patches add the same config file mechanism as C2 **plus** a runtime initialization
condition.  The `/exec/init?token=<secret>` endpoint (or equivalent) must be called
first; it validates the token against a value read from the config file and, if it
matches, sets a global `exec_initialized = 1`.  The main guard checks:

```c
if (exec_cfg.enabled && exec_initialized && /* url check */ ...)
```

angr must reason about the inter-request state (`exec_initialized`) as well as the
config-file-sourced values to determine exploitability.

---

### PoC conventions

- All PoC scripts use `bash` with `set -euo pipefail`.
- `SERVER_PID=0` is declared before the `trap cleanup EXIT` line.
- Primary port: `18NNN` (where NNN is the zero-padded sample number).
- Negative-control port: `19NNN`.
- Marker file: `/tmp/poc_NNN_marker`; written by the exploit payload `id>/tmp/poc_NNN_marker`.
- `system()` output goes to the server's inherited stdout/stderr, not the HTTP response body.

---

### Evaluation protocol

For a given sample, the tool under test receives:

1. The patched binary
2. A runtime configuration description (the flags / config file that were used to start
   the server in the PoC)

Expected outputs:

| Ground truth | Expected answer |
|-------------|-----------------|
| Gate enabled, no sanitization (S1) | **Exploitable** |
| Gate enabled, bypassable filter (S2) | **Exploitable** (via `;` bypass) |
| Gate enabled, strict sanitization active (S3 with `--strict-exec`) | **Not exploitable** |
| Gate disabled | **Not exploitable** |
| Gate enabled, S3 but sanitization not activated (S3 without `--strict-exec`) | **Exploitable** |


## Results

TBD