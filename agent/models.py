from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class Sense(str, Enum):
    present = "present"
    absent = "absent"


class ConfigurationType(str, Enum):
    flag = "flag"
    file = "file"
    runtime_state = "runtime_state"


class ConfigurationOption(BaseModel):
    configuration_type: ConfigurationType
    configuration_parameter: str
    configuration_value: Optional[str] = None
    sense: Sense = Sense.present

    def __hash__(self) -> int:
        return hash((self.configuration_type, self.configuration_parameter,
                     self.configuration_value, self.sense))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ConfigurationOption):
            return False
        return (self.configuration_type == other.configuration_type and
                self.configuration_parameter == other.configuration_parameter and
                self.configuration_value == other.configuration_value and
                self.sense == other.sense)


class VerifyFailure(str, Enum):
    WRONG_ROUTE      = "WRONG_ROUTE"       # 404 on /exec or target route
    WRONG_CONFIG_KEY = "WRONG_CONFIG_KEY"  # server responded but no effect
    WRONG_TOKEN      = "WRONG_TOKEN"       # C3 /exec/init rejected token
    SERVER_CRASH     = "SERVER_CRASH"      # binary exited unexpectedly
    PORT_CONFLICT    = "PORT_CONFLICT"     # could not bind to port


class CausalFailure(str, Enum):
    CONFIG_TO_VAR  = "config_to_variable"   # can't confirm option sets gate variable
    VAR_TO_GATE    = "variable_to_gate"     # can't confirm variable is tested in gate
    GATE_TO_SINK   = "gate_to_sink"         # can't confirm gate leads to sink
    INPUT_TO_ARG   = "input_to_argument"    # can't confirm input reaches sink arg
    INCONCLUSIVE   = "inconclusive"         # insufficient evidence


class Verdict(str, Enum):
    Exploitable    = "Exploitable"
    NotExploitable = "NotExploitable"
    Inconclusive   = "Inconclusive"


class Sink(BaseModel):
    addr: int
    function: str     # "system", "execve", "popen", etc.
    arg_index: int    # which argument carries tainted data
    caller: str       # name of the function containing this call site


class SinkResult(BaseModel):
    sink: Sink
    verdict: Verdict
    preconditions: List[ConfigurationOption] = []
    attempts: int = 0
    evidence: Dict[str, Any] = {}


class AnalysisResult(BaseModel):
    binary: str
    verdict: Verdict
    preconditions: List[ConfigurationOption]
    sink_results: List[SinkResult]


# Dangerous function names the agent looks for
DANGEROUS_FUNCTIONS = {
    "system", "execve", "execvp", "execvpe",
    "execl", "execle", "execlp", "popen",
}
