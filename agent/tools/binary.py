"""Low-level binary analysis tools: strings, binary_info, read_bytes, objdump."""

from __future__ import annotations

import re
import subprocess
from typing import Any, Dict, List, Optional


def strings(binary: str, min_length: int = 4) -> List[str]:
    """Extract printable strings from a binary."""
    result = subprocess.run(
        ["strings", "-n", str(min_length), binary],
        capture_output=True, text=True, timeout=15,
    )
    return [s for s in result.stdout.splitlines() if s]


def binary_info(binary: str) -> Dict[str, Any]:
    """Return metadata dict: arch, bits, stripped, pie, endian.

    Uses ``file`` and ``readelf``; gracefully degrades if either is missing.
    """
    info: Dict[str, Any] = {
        "arch": "unknown",
        "bits": 64,
        "stripped": True,
        "pie": False,
        "endian": "little",
    }

    try:
        file_out = subprocess.run(
            ["file", binary], capture_output=True, text=True, timeout=5,
        ).stdout.lower()

        if "x86-64" in file_out or "x86_64" in file_out:
            info["arch"], info["bits"] = "x86_64", 64
        elif "intel 80386" in file_out or "i386" in file_out:
            info["arch"], info["bits"] = "x86", 32
        elif "aarch64" in file_out:
            info["arch"], info["bits"] = "aarch64", 64
        elif "arm" in file_out:
            info["arch"], info["bits"] = "arm", 32

        info["stripped"] = "not stripped" not in file_out
        info["pie"]      = "pie executable" in file_out or "position independent" in file_out
        info["endian"]   = "big" if ("big-endian" in file_out or " msb" in file_out) else "little"
    except FileNotFoundError:
        pass

    try:
        re_out = subprocess.run(
            ["readelf", "-h", binary], capture_output=True, text=True, timeout=5,
        ).stdout
        if "EXEC" in re_out:
            info["pie"] = False
        elif "DYN" in re_out:
            info["pie"] = True
    except FileNotFoundError:
        pass

    return info


def read_bytes(binary: str, offset: int, length: int) -> bytes:
    """Read raw bytes from the binary at *offset* for *length* bytes."""
    with open(binary, "rb") as fh:
        fh.seek(offset)
        return fh.read(length)


def objdump(
    binary: str,
    function: Optional[str] = None,
    section: Optional[str] = None,
    start_addr: Optional[int] = None,
    stop_addr: Optional[int] = None,
) -> str:
    """Disassemble binary.  Optional filters: named function, section, address range.

    Returns Intel-syntax disassembly text.  Truncated to 500 lines to avoid
    flooding the LLM context.
    """
    cmd = ["objdump", "-d", "--no-show-raw-insn", "-M", "intel"]
    if section:
        cmd += ["-j", section]
    cmd.append(binary)

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    text = result.stdout

    if function:
        lines = text.splitlines()
        out: List[str] = []
        in_fn = False
        for line in lines:
            if re.match(rf"[0-9a-f]+ <{re.escape(function)}(?:@[^>]*)?>:", line):
                in_fn = True
            elif in_fn and re.match(r"[0-9a-f]+ <[^>]+>:", line):
                break
            if in_fn:
                out.append(line)
        text = "\n".join(out)

    elif start_addr is not None:
        lines = text.splitlines()
        out = []
        in_range = False
        for line in lines:
            m = re.match(r"\s*([0-9a-f]+):", line)
            if m:
                addr = int(m.group(1), 16)
                if addr >= start_addr:
                    in_range = True
                if stop_addr is not None and addr >= stop_addr:
                    break
            if in_range:
                out.append(line)
        text = "\n".join(out)

    lines = text.splitlines()
    if len(lines) > 500:
        lines = lines[:500] + [f"... ({len(lines) - 500} lines truncated)"]
    return "\n".join(lines)
