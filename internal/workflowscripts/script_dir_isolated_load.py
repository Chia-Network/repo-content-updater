"""Trusted loader resolve graph (single public spine from cold_start)."""

from __future__ import annotations

import types
from pathlib import Path

from isolated_module_exec import load_module_isolated, register_util_from_scripts_dir
from scripts_dir_module_loader import exec_module_scrubbing_script_dir

__all__ = (
    "exec_module_scrubbing_script_dir",
    "load_module_isolated",
    "register_util_from_scripts_dir",
    "resolve_trusted_formatter_loader_for_dir",
)


def resolve_trusted_formatter_loader_for_dir(script_dir: Path) -> types.ModuleType:
    """Load trusted_formatter_loader + formatter policy siblings (scripts-dir isolation)."""
    script_dir = script_dir.resolve()
    util = register_util_from_scripts_dir(script_dir)
    util.load_module_isolated(
        script_dir / "formatter_runtime_bundle.py",
        "formatter_runtime_bundle",
    )
    loader_path = script_dir / "trusted_formatter_loader.py"
    if not loader_path.is_file():
        raise RuntimeError(f"Missing {loader_path}")
    loader_mod = util.load_module_isolated(loader_path, "trusted_formatter_loader")
    loader_mod.ensure_formatter_sibling_modules(script_dir)
    return loader_mod
