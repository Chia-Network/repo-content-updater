"""Stdlib-only module isolation and trusted formatter loader resolve spine."""

from __future__ import annotations

import sys
import types
from pathlib import Path

from scripts_dir_module_loader import bootstrap_module_from_scripts_dir


def load_module_isolated(
    script_path: Path,
    module_name: str | None = None,
) -> types.ModuleType:
    """Register and exec a module without leaving its directory on sys.path."""
    script_path = script_path.resolve()
    name = module_name or f"isolated_{script_path.stem}"
    existing = sys.modules.get(name)
    if existing is not None:
        existing_file = getattr(existing, "__file__", None)
        if existing_file and Path(existing_file).resolve() == script_path:
            return existing
    return bootstrap_module_from_scripts_dir(script_path.parent, script_path.name, name)


def register_util_from_scripts_dir(script_dir: Path) -> types.ModuleType:
    """Prime scripts_dir_module_loader + isolated_module_exec for trusted_formatter_loader."""
    script_dir = script_dir.resolve()
    name = "isolated_module_exec"
    path = script_dir / f"{name}.py"
    existing = sys.modules.get(name)
    if existing is not None:
        existing_file = getattr(existing, "__file__", None)
        if existing_file and Path(existing_file).resolve() == path.resolve():
            return existing
    bootstrap_module_from_scripts_dir(
        script_dir, "scripts_dir_module_loader.py", "scripts_dir_module_loader"
    )
    if not path.is_file():
        raise RuntimeError(f"Missing {path}")
    return load_module_isolated(path, name)


def resolve_trusted_formatter_loader_for_dir(script_dir: Path) -> types.ModuleType:
    """Load trusted_formatter_loader + formatter policy siblings (scripts-dir isolation)."""
    script_dir = script_dir.resolve()
    util = sys.modules.get("isolated_module_exec")
    if util is None:
        raise RuntimeError(
            "isolated_module_exec must be registered before resolve_trusted_formatter_loader_for_dir"
        )
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
