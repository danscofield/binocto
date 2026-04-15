# Synthetic Command-Injection Corpus

A corpus of C/C++ web servers patched with synthetic, config-gated command-injection
vulnerabilities, designed for evaluating agentic vulnerability analysis tools that
combine Joern CPG static analysis with angr symbolic execution.

---

## Purpose

Each sample asks the same yes/no question: *given this runtime configuration, is the
`system()` sink reachable from an attacker-controlled HTTP parameter?*  The three axes
independently vary how hard the answer is to compute statically.

---

## Directory layout

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

## Three-Axis Taxonomy

### C axis — Config Gate Complexity

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

### I axis — Input Flow

How many transforms lie between the raw HTTP query parameter and the `system()` call?

| Label | Name | Mechanism |
|-------|------|-----------|
| **I1** | Direct | `cmd` pointer from URL query string passed verbatim to `system(cmd)` |
| **I2** | Buffered | `snprintf(shell_cmd, sizeof(shell_cmd), "sh -c '%s' 2>/dev/null", cmd); system(shell_cmd);` — one intermediate buffer |
| **I3** | Struct dispatch | `exec_args_t args = {.cmd = cmd, .flags = 0}; dispatch_exec(&args);` where `dispatch_exec` calls `system(args->cmd)` — pointer through a struct and a helper function |

### S axis — Sanitization

What filtering (if any) is applied to `cmd` before `system()`?

| Label | Name | Mechanism | Bypass |
|-------|------|-----------|--------|
| **S1** | None | No check | N/A — no sanitization to bypass |
| **S2** | Bypassable filter | `if (strchr(cmd, '\|') != NULL) { reject 403; }` — blocks pipe character | Use `;` or bare `>` redirection instead |
| **S3** | Config-gated sanitization | `static int strict_exec = 0;` set by `--strict-exec`; `if (strict_exec && strpbrk(cmd, "\|;&\`$") != NULL) { reject; }` — full metachar check only when flag is present | Omit `--strict-exec` when starting server; sanitization is never activated |

---

## Axis combinations and corpus coverage

All 5 × 3 × 3 = 45 axis combinations are represented (some more than once):

```
C1   × I{1,2,3} × S{1,2,3}   — 9 combos, ~45 samples (001–116 range)
C1b  × I{1,2,3} × S{1,2,3}   — 9 combos, ~36 samples (001–116 range)
C1c  × I{1,2,3} × S{1,2,3}   — 9 combos, ~35 samples (001–116 range)
C2   × I{1,2,3} × S{1,2,3}   — 9 combos, ~36 samples (117–152 range)
C3   × I{1,2,3} × S{1,2,3}   — 9 combos, ~36 samples (153–188 range)
```

---

## Servers

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

## Sample artifacts

Every sample directory contains exactly these files:

| File | Description |
|------|-------------|
| `PROVENANCE` | Structured text: PACKAGE, COMMIT, SOURCE, AXES, DESCRIPTION, CONFIG_GATE, INPUT_FLOW, SANITIZATION, SINK, CHANGED FILES, EXPLOIT, NOTES |
| `patch.diff` | Unified diff (`diff -u --label "a/file" --label "b/file"`) applied with `patch -p1` |
| `build.sh` | Copies unmodified source to a temp dir, applies patch, compiles binary into the sample directory |
| `PoC.sh` | Starts patched binary with gate enabled, sends exploit, verifies RCE via file write, then runs negative control (gate disabled → 404) |
| `<binary>` | Pre-built patched binary; `build.sh` regenerates it deterministically |

---

## C2 config file format

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

## C3 config file + runtime state

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

## PoC conventions

- All PoC scripts use `bash` with `set -euo pipefail`.
- `SERVER_PID=0` is declared before the `trap cleanup EXIT` line.
- Primary port: `18NNN` (where NNN is the zero-padded sample number).
- Negative-control port: `19NNN`.
- Marker file: `/tmp/poc_NNN_marker`; written by the exploit payload `id>/tmp/poc_NNN_marker`.
- `system()` output goes to the server's inherited stdout/stderr, not the HTTP response body.

---

## Evaluation protocol

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
