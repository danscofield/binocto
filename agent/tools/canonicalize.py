"""Normalize ConfigurationOption fields to match ground-truth format.

Ground-truth conventions (from corpus/samples/*/ground_truth.json):
  flag          → '--exec-mode'   (leading dashes, hyphen-separated, lowercase)
  file          → 'exec_mode'     (no dashes, underscore-separated, lowercase)
  runtime_state → '/exec/init'    (URL path with leading slash)

Values:
  file booleans → '1' (true) or '0' (false)
  flag values   → None (presence-only) or literal string
  runtime_state → literal token string
"""

from __future__ import annotations

import re
from typing import Optional

from models import ConfigurationOption, ConfigurationType


def canonicalize(opt: ConfigurationOption) -> ConfigurationOption:
    """Return a new ConfigurationOption with normalised parameter and value."""
    return opt.model_copy(update={
        "configuration_parameter": _canon_param(opt),
        "configuration_value":     _canon_value(opt),
    })


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _canon_param(opt: ConfigurationOption) -> str:
    p = opt.configuration_parameter

    if opt.configuration_type == ConfigurationType.flag:
        # Strip any existing leading dashes, then re-add correct prefix.
        bare = p.lstrip("-")
        prefix = "-" if len(bare) == 1 else "--"
        # Underscores → hyphens in the name portion; lowercase.
        p = prefix + bare.replace("_", "-").lower()

    elif opt.configuration_type == ConfigurationType.file:
        # Strip leading dashes; hyphens → underscores; lowercase.
        p = p.lstrip("-").replace("-", "_").lower()

    elif opt.configuration_type == ConfigurationType.runtime_state:
        # Ensure leading slash (URL path form).
        if not p.startswith("/"):
            p = "/" + p

    return p


def _canon_value(opt: ConfigurationOption) -> Optional[str]:
    v = opt.configuration_value
    if v is None:
        return v

    if opt.configuration_type == ConfigurationType.file:
        norm = v.strip().lower()
        if norm in {"true", "yes", "on", "enable", "enabled", "1"}:
            return "1"
        if norm in {"false", "no", "off", "disable", "disabled", "0"}:
            return "0"
        return v.strip()

    # flag and runtime_state: preserve as-is, just strip whitespace.
    return v.strip()
