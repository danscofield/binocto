"""Shared utilities for analysis nodes."""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, List

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import BaseTool
from langchain_core.tools import tool as lc_tool

MODEL = os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6")
MAX_TOOL_ITERATIONS = int(os.environ.get("AGENT_MAX_ITER", "100"))

log = logging.getLogger("agent")


def get_llm() -> ChatAnthropic:
    return ChatAnthropic(model=MODEL, temperature=0)


def run_analysis_agent(
    system_prompt: str,
    user_message:  str,
    tools:         List[BaseTool],
    node_name:     str = "",
    max_iter:      int = MAX_TOOL_ITERATIONS,
) -> str:
    """Run a tool-calling ReAct loop.

    Returns the final text response from the LLM (after it stops calling tools).
    Raises RuntimeError if max_iter is exceeded without a final answer.
    """
    llm = get_llm().bind_tools(tools)
    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_message),
    ]

    label = f"[{node_name}] " if node_name else ""
    log.info("%sstarting  (tools: %s)", label, [t.name for t in tools] or "none")
    log.debug("%suser_message:\n%s", label, user_message)

    # When this many iterations remain, inject a "final answer now" message so
    # the LLM has a chance to summarise before the hard limit is hit.
    _FINAL_NUDGE_AT = max(1, max_iter - 3)
    _nudged = False

    iteration = 0
    for iteration in range(max_iter):
        t0 = time.monotonic()
        response: AIMessage = llm.invoke(messages)
        elapsed = time.monotonic() - t0

        if not getattr(response, "tool_calls", None):
            log.info("%sLLM final answer  (%.1fs, %d iter)",
                     label, elapsed, iteration + 1)
            log.debug("%sfinal response:\n%s", label, response.content[:2000])
            return response.content

        log.info("%sLLM called %d tool(s)  (%.1fs)",
                 label, len(response.tool_calls), elapsed)
        messages.append(response)

        tool_map = {t.name: t for t in tools}
        for tc in response.tool_calls:
            tool = tool_map.get(tc["name"])
            args_repr = ", ".join(f"{k}={repr(v)[:60]}" for k, v in tc["args"].items())
            log.info("%s  → %s(%s)", label, tc["name"], args_repr)

            if tool is None:
                result = f"ERROR: unknown tool {tc['name']}"
            else:
                try:
                    t1 = time.monotonic()
                    result = tool.invoke(tc["args"])
                    log.debug("%s    result (%.1fs):\n%s",
                              label, time.monotonic() - t1, str(result)[:1000])
                except Exception as exc:
                    result = f"TOOL_ERROR: {exc}"
                    log.warning("%s    tool error: %s", label, exc)

            messages.append(
                ToolMessage(content=str(result), tool_call_id=tc["id"])
            )

        # Inject final-answer nudge once, just before the iteration limit
        if not _nudged and iteration >= _FINAL_NUDGE_AT:
            _nudged = True
            log.warning("%snudging LLM for final answer at iter %d/%d",
                        label, iteration + 1, max_iter)
            messages.append(HumanMessage(
                content=(
                    "IMPORTANT: You have used most of your tool call budget. "
                    "Stop calling tools now and provide your FINAL ANSWER in the "
                    "required JSON format, based on everything you have found so far. "
                    "If uncertain, make your best guess — do not call more tools."
                )
            ))

    raise RuntimeError(
        f"run_analysis_agent: max iterations ({max_iter}) exceeded without final answer"
    )


def make_joern_raw_tool(cpg_path: str) -> BaseTool:
    """Return a joern_raw @tool bound to *cpg_path*.

    Centralised here so every node gets the same docstring — in particular the
    list of valid CPG traversal types, which prevents the LLM generating queries
    against non-existent traversals (e.g. cpg.string, cpg.variable).
    """
    from tools import raw_query  # local import to avoid circular dependency

    @lc_tool
    def joern_raw(scala_body: str) -> str:
        """Run an arbitrary Joern CPGql query. Use only when typed helpers are insufficient.

        VALID top-level CPG traversals in Ghidra-frontend CPGs:
          cpg.call        — all call sites; the primary analysis primitive
          cpg.method      — functions / methods
          cpg.literal     — string and numeric literals
          cpg.parameter   — function parameters
          cpg.local       — local variable declarations (usually empty in Ghidra CPGs)

        DOES NOT EXIST — will cause a compile error:
          cpg.string      → use cpg.literal instead
          cpg.variable    → use cpg.local or search cpg.call argument code
          cpg.identifier  → empty in Ghidra CPGs; use cpg.call / cpg.literal

        Addresses: lineNumber returns the virtual address as a plain decimal Int.
        ALWAYS use string interpolation to format — do NOT call .toHexString on the
        result of getOrElse, as mixing Int/Long causes a type error:
          CORRECT:   s"${m.name} @ ${m.lineNumber.getOrElse(-1)}"
          INCORRECT: m.lineNumber.getOrElse(-1L).toHexString   ← E008 type error

        When iterating cpg.method results, access .name directly on the Method node:
          CORRECT:   cpg.method.foreach(m => println(m.name))
          INCORRECT: cpg.method.foreach(m => println(m.method.name))  ← wrong

        Example — find all literals containing "exec":
          cpg.literal.filter(_.code.contains("exec")).foreach(l =>
            println(s"${l.method.name} @ ${l.lineNumber.getOrElse(-1)}: ${l.code}")
          )

        Example — calls in an address range (use Long suffix only in filter, not getOrElse):
          cpg.call.filter(c => c.lineNumber.exists(ln => ln >= 0xc000L && ln <= 0xd000L))
            .foreach(c => println(s"${c.name} @ ${c.lineNumber.getOrElse(-1)}"))

        Args:
            scala_body: Scala code to execute (inserted into @main def exec()).
        """
        return raw_query(cpg_path, scala_body)

    return joern_raw


def extract_json_block(text: str) -> Dict[str, Any]:
    """Extract the first JSON object/array from *text*."""
    import re
    m = re.search(r"```(?:json)?\s*(\{[\s\S]*?\}|\[[\s\S]*?\])\s*```", text)
    if m:
        return json.loads(m.group(1))
    for start_char, end_char in (("{", "}"), ("[", "]")):
        idx = text.find(start_char)
        if idx != -1:
            depth = 0
            for i, ch in enumerate(text[idx:], idx):
                if ch == start_char:
                    depth += 1
                elif ch == end_char:
                    depth -= 1
                    if depth == 0:
                        return json.loads(text[idx: i + 1])
    raise ValueError(f"No JSON found in:\n{text[:400]}")
