"""synthesize_preconditions node: build (or revise) the ConfigurationOption hypothesis.

Runs in a loop with causal_verify.  On revision passes, verify_failure_reason
provides feedback about which causal link failed and why.

No corpus-specific taxonomy labels appear here.  The agent reasons about
mechanisms (cli_flag / config_file / runtime_sequence) and produces
typed ConfigurationOption objects.  The scoring layer derives axis labels later.
"""

from __future__ import annotations

import json
from typing import List

from models import ConfigurationOption, ConfigurationType, Sense
from nodes.common import extract_json_block, run_analysis_agent
from state import SinkState
from tools.canonicalize import canonicalize


_SYSTEM = """\
You are a binary analysis agent synthesising the set of configuration
preconditions required to exploit a vulnerability.

You have already determined:
  - gate_source: how the sink is guarded (cli_flag / config_file / runtime_sequence)
  - gate_conditions: what variables are checked and where they come from
  - sanitization: whether a sanitization check exists and whether it is config-gated
  - input_path: the HTTP route and parameter that carry the payload

Build a list of ConfigurationOption objects AND a causal chain description.

Each ConfigurationOption has four fields:

  configuration_type:
    "flag"         – a command-line flag (set at process startup via argv)
    "file"         – a key=value pair in a config file read at startup
    "runtime_state"– a runtime condition established by a prior HTTP request

  configuration_parameter: the exact name of the flag, key, or HTTP route
    - Flags use the CLI spelling, e.g. "--exec-mode"
    - File keys use the key name as it appears in the config, e.g. "exec_mode"
    - Runtime state uses the HTTP path, e.g. "/exec/init"

  configuration_value:
    - Flags: null (presence is sufficient)
    - File keys: the string value that enables the feature, e.g. "1"
    - Runtime state: the token/secret required, e.g. "s3cr3t"

  sense:
    "present" – this option must be set / active for exploitation
    "absent"  – this option must NOT be set (i.e. its absence enables exploitation)

Rules for ConfigurationOption:
  - Only include conditions that are NECESSARY for the sink to be reachable with
    attacker-controlled input.  Ask: "If this condition were absent, could the
    attacker still reach the sink?"  If yes, omit it.

  - ENABLING gate (include, sense "present"): without this option the code path
    to the sink is never taken.  Example: --exec-mode where exec_mode==0 causes
    an unconditional skip of the entire exec handler.

  - RESTRICTING gate (omit): the option limits WHO can reach the sink, but the
    sink is reachable even without the option — just by a less-authenticated or
    differently-configured client.  Example: --auth enables HTTP Basic auth; without
    it the same endpoint is accessible to any client.  The vulnerability exists in
    both states; --auth is not a precondition.

  - COMPLETENESS for multiple flags: if gate_conditions lists N separate variables
    that are each independently tested (e.g. exec_gate_a, exec_gate_b, exec_gate_c),
    produce a separate ConfigurationOption for EVERY one of them.  Missing any one
    makes the precondition set incomplete — an attacker who satisfies only a subset
    cannot reach the sink.

  - A sanitization check that BLOCKS exploitation when active (config_gated=true)
    → add an "absent" entry for the flag/key that activates it

  - For runtime_sequence: include BOTH any underlying config-file gate
    (type "file", sense "present") AND the init endpoint
    (type "runtime_state", sense "present", value = exact token).
    The token MUST be the literal string the init handler validates — look for
    init_token in the gate_conditions data.  If it is not present there, set
    configuration_value to null and note it is unknown rather than guessing.

  - Do NOT invent conditions not supported by the analysis findings.
    Every configuration_parameter you report must come verbatim from the
    gate_conditions data above — do not guess or infer flag names that do
    not appear there.  If a gate variable lacks a confirmed flag_or_key,
    omit it rather than substituting a plausible-sounding name.

Return a JSON object with two fields:

{
  "preconditions": [
    {"configuration_type":"flag","configuration_parameter":"--exec-mode","configuration_value":null,"sense":"present"},
    {"configuration_type":"file","configuration_parameter":"exec_mode","configuration_value":"1","sense":"present"},
    {"configuration_type":"runtime_state","configuration_parameter":"/exec/init","configuration_value":"s3cr3t","sense":"present"}
  ],
  "causal_chain": {
    "config_to_variable": "description of how the config option sets the gate variable",
    "variable_to_gate": "description of how the variable is tested in the branch guarding the sink",
    "gate_to_sink": "description of the path from satisfied branch to the sink call",
    "input_to_argument": "description of how HTTP input becomes the sink's argument"
  }
}
"""


def synthesize_preconditions_node(state: SinkState) -> dict:
    gate_source    = state.get("gate_source", "cli_flag")
    gate_conditions = state.get("gate_conditions", [])
    sanitization   = state.get("sanitization", {})
    input_path     = state.get("input_path", {})
    failure_reason = state.get("verify_failure_reason")
    attempt        = state.get("verify_attempts", 0)
    prev_hypothesis = state.get("precondition_hypothesis", [])

    failure_context = ""
    if failure_reason and prev_hypothesis:
        prev_json = json.dumps([o.model_dump() for o in prev_hypothesis], indent=2)
        failure_context = (
            f"\n\nPREVIOUS HYPOTHESIS (attempt {attempt}):\n{prev_json}\n"
            f"VERIFICATION FAILED ON LINK: {failure_reason}\n"
            "Revise the hypothesis to fix the specific broken link:\n"
            "  config_to_variable → the option name or value is wrong; the causal_verify\n"
            "    evidence will say what the binary actually uses — adopt those exact values.\n"
            "    For flags: check uppercase vs lowercase, short vs long form.\n"
            "    For runtime_state tokens: the verified token is in the evidence; use it.\n"
            "  variable_to_gate   → wrong variable identified; check the evidence for the\n"
            "    correct variable name/address that is actually tested in the branch.\n"
            "  gate_to_sink       → extra condition between branch and sink; add the\n"
            "    missing condition as an additional precondition.\n"
            "  input_to_argument  → wrong entry point or parameter; update from the evidence.\n"
        )

    user_msg = (
        f"gate_source: {gate_source}\n"
        f"gate_conditions:\n{json.dumps(gate_conditions, indent=2)}\n"
        f"input_path: {json.dumps(input_path, indent=2)}\n"
        f"sanitization: {json.dumps(sanitization, indent=2)}"
        f"{failure_context}"
    )

    raw_data: dict = {}
    try:
        response = run_analysis_agent(
            system_prompt=_SYSTEM,
            user_message=user_msg,
            tools=[],   # pure reasoning — no tool calls
            node_name="synthesize_preconditions",
        )
        try:
            parsed = extract_json_block(response)
            if isinstance(parsed, dict):
                raw_data = parsed
            elif isinstance(parsed, list):
                # Backward-compat: plain array response → treat as preconditions only
                raw_data = {"preconditions": parsed, "causal_chain": {}}
        except ValueError:
            raw_data = {}
    except (RuntimeError, ValueError):
        raw_data = {}

    raw_list = raw_data.get("preconditions", [])
    if not isinstance(raw_list, list):
        raw_list = []

    options: List[ConfigurationOption] = []
    for entry in raw_list:
        try:
            opt = ConfigurationOption(**entry)
            options.append(canonicalize(opt))
        except Exception:
            continue

    causal_chain = raw_data.get("causal_chain") or {}

    return {
        "precondition_hypothesis": options,
        "causal_chain": causal_chain,
    }
