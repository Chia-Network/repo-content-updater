"""Trusted loader resolve graph (uses isolated_module_exec for registration)."""

from __future__ import annotations

import types
from pathlib import Path

from isolated_module_exec import load_module_isolated, register_util_from_scripts_dir
from module_exec_scrub import exec_module_scrubbing_script_dir

__all__ = (
    "exec_module_scrubbing_script_dir",
    "load_module_isolated",
    "register_util_from_scripts_dir",
    "resolve_trusted_formatter_loader_for_dir",
)


def resolve_trusted_formatter_loader_for_dir(script_dir: Path) -> types.ModuleType:
    """Isolated bootstrap + loader + formatter policy sibling modules."""
    script_dir = script_dir.resolve()
    util = register_util_from_scripts_dir(script_dir)
    bootstrap = util.load_module_isolated(
        script_dir / "trusted_formatter_loader_bootstrap.py",
        "trusted_formatter_loader_bootstrap",
    )
    loader_path = script_dir / "trusted_formatter_loader.py"
    if not loader_path.is_file():
        raise RuntimeError(f"Missing {loader_path}")
    loader_mod = bootstrap.load_loader_module(loader_path)
    loader_mod.ensure_formatter_sibling_modules(script_dir)
    return loader_mod
