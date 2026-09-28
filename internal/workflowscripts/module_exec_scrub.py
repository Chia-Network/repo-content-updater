"""Import-stable re-export of scripts_dir_module_loader scrub primitives."""

from __future__ import annotations

from scripts_dir_module_loader import (
    bootstrap_module_from_scripts_dir,
    exec_module_scrubbing_script_dir,
)

__all__ = (
    "bootstrap_module_from_scripts_dir",
    "exec_module_scrubbing_script_dir",
)
