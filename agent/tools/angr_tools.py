"""angr-based verification tools.

Two modes:
  angr_find_path      – symbolic execution: can a path to find_addrs exist?
  angr_concrete_trace – run with concrete (agent-synthesised) args, confirm
                        that find_addrs are visited

Both run the angr logic in a subprocess so that angr's heavy JVM-free Python
env doesn't interfere with LangGraph's event loop, and so that OOM/timeout in
angr doesn't kill the main agent process.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class SymbolicResult:
    sat:         bool
    model:       Dict[str, Any] = field(default_factory=dict)  # var → concrete value
    path_length: int = 0
    error:       Optional[str] = None


@dataclass
class TraceResult:
    hit_targets: List[int] = field(default_factory=list)  # addrs actually reached
    stdout:      str = ""
    stderr:      str = ""
    exit_code:   int = -1
    error:       Optional[str] = None


# ---------------------------------------------------------------------------
# Embedded angr scripts (written to tmp files at call time)
# ---------------------------------------------------------------------------

_FIND_PATH_SCRIPT = r"""
import sys, json, angr, claripy

binary      = sys.argv[1]
find_addrs  = [int(x, 16) for x in sys.argv[2].split(",") if x]
avoid_addrs = [int(x, 16) for x in sys.argv[3].split(",") if x]
# symbolic_args: "sym" means make symbolic, anything else is a literal string
sym_specs   = sys.argv[4].split("||") if sys.argv[4] else []
timeout     = int(sys.argv[5])

proj = angr.Project(binary, auto_load_libs=False)

args = [proj.filename]
sym_vars: dict = {}
for i, spec in enumerate(sym_specs):
    if spec == "sym":
        v = claripy.BVS(f"arg_{i}", 8 * 64)
        sym_vars[f"arg_{i}"] = v
        args.append(v)
    else:
        args.append(spec)

state = proj.factory.entry_state(args=args)
simgr = proj.factory.simgr(state)

try:
    simgr.explore(find=find_addrs, avoid=avoid_addrs, timeout=timeout)
    if simgr.found:
        found = simgr.found[0]
        model = {}
        for name, sym in sym_vars.items():
            try:
                model[name] = found.solver.eval(sym, cast_to=bytes).decode(errors="replace")
            except Exception as exc:
                model[name] = str(exc)
        bbl_count = len(list(found.history.bbl_addrs))
        print(json.dumps({"sat": True, "model": model, "path_length": bbl_count}))
    else:
        print(json.dumps({"sat": False, "model": {}, "path_length": 0}))
except Exception as exc:
    print(json.dumps({"sat": False, "model": {}, "path_length": 0, "error": str(exc)}))
"""

_CONCRETE_TRACE_SCRIPT = r"""
import sys, json, angr

binary      = sys.argv[1]
args        = sys.argv[2].split("||") if sys.argv[2] else []
find_addrs  = [int(x, 16) for x in sys.argv[3].split(",") if x]
timeout     = int(sys.argv[4])

proj  = angr.Project(binary, auto_load_libs=False)
state = proj.factory.entry_state(args=[binary] + args)
simgr = proj.factory.simgr(state)

try:
    simgr.explore(find=find_addrs, timeout=timeout)
    hit = [a for a in find_addrs if simgr.found] if simgr.found else []
    print(json.dumps({"hit_targets": hit, "exit_code": 0}))
except Exception as exc:
    print(json.dumps({"hit_targets": [], "exit_code": -1, "error": str(exc)}))
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def angr_find_path(
    binary:        str,
    find_addrs:    List[int],
    avoid_addrs:   Optional[List[int]] = None,
    symbolic_args: Optional[List[str]] = None,
    timeout:       int = 60,
) -> SymbolicResult:
    """Symbolic execution: is there a satisfiable path from entry to *find_addrs*?

    *symbolic_args*: list of "sym" (make that argv slot symbolic) or a literal
    string.  E.g. ["--exec-mode", "sym"] to fix the first arg and make the
    second symbolic.
    """
    avoid_addrs   = avoid_addrs   or []
    symbolic_args = symbolic_args or []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as fh:
        fh.write(_FIND_PATH_SCRIPT)
        script = fh.name

    try:
        find_str  = ",".join(hex(a) for a in find_addrs)
        avoid_str = ",".join(hex(a) for a in avoid_addrs)
        args_str  = "||".join(symbolic_args)

        result = subprocess.run(
            ["python3", script, binary, find_str, avoid_str, args_str, str(timeout)],
            capture_output=True, text=True, timeout=timeout + 15,
        )
        last_line = (result.stdout.strip().splitlines() or ["{}"])[-1]
        data = json.loads(last_line)
        return SymbolicResult(
            sat=data.get("sat", False),
            model=data.get("model", {}),
            path_length=data.get("path_length", 0),
            error=data.get("error"),
        )
    except Exception as exc:
        return SymbolicResult(sat=False, error=str(exc))
    finally:
        os.unlink(script)


def angr_concrete_trace(
    binary:      str,
    args:        Optional[List[str]] = None,
    find_addrs:  Optional[List[int]] = None,
    timeout:     int = 15,
) -> TraceResult:
    """Concrete execution trace: run binary with *args*, check if *find_addrs* hit.

    Uses angr in concrete mode (no symbolic variables).  Useful to confirm
    that an agent-synthesised input actually reaches the vulnerable code path.
    """
    args       = args       or []
    find_addrs = find_addrs or []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as fh:
        fh.write(_CONCRETE_TRACE_SCRIPT)
        script = fh.name

    try:
        args_str = "||".join(args)
        find_str = ",".join(hex(a) for a in find_addrs)

        result = subprocess.run(
            ["python3", script, binary, args_str, find_str, str(timeout)],
            capture_output=True, text=True, timeout=timeout + 5,
        )
        last_line = (result.stdout.strip().splitlines() or ["{}"])[-1]
        data = json.loads(last_line)
        return TraceResult(
            hit_targets=data.get("hit_targets", []),
            exit_code=data.get("exit_code", result.returncode),
            stdout=result.stdout,
            stderr=result.stderr,
            error=data.get("error"),
        )
    except Exception as exc:
        return TraceResult(error=str(exc))
    finally:
        os.unlink(script)
