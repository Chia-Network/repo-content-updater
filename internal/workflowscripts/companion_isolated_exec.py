"""Canonical scripts-dir isolation for workflow companion modules (stdlib only)."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path


def exec_module_isolated_from_scripts_dir(
    spec: importlib.util.ModuleSpec,
    module: types.ModuleType,
    script_path: Path,
) -> None:
    """Thin alias: scrub + exec via script_dir_isolated_load."""
    util = sys.modules.get("script_dir_isolated_load")
    if util is None:
        raise RuntimeError(
            "script_dir_isolated_load must be registered before companion exec"
        )
    util.exec_module_scrubbing_script_dir(spec, module, script_path)


def exec_companion_module(
    script_path: Path,
    module_name: str | None = None,
) -> types.ModuleType:
    """Load a workflow companion module with its directory scrubbed from sys.path."""
    util = sys.modules.get("script_dir_isolated_load")
    if util is None:
        raise RuntimeError(
            "script_dir_isolated_load must be registered before exec_companion_module"
        )
    script_path = script_path.resolve()
    name = module_name or f"companion_{script_path.stem}"
    return util.load_module_isolated(script_path, name)


def ensure_companion_isolated_exec(script_dir: Path) -> types.ModuleType:
    """Ensure companion_isolated_exec is registered from the trusted scripts directory."""
    script_dir = script_dir.resolve()
    existing = sys.modules.get("companion_isolated_exec")
    if existing is not None:
        existing_file = getattr(existing, "__file__", None)
        expected = script_dir / "companion_isolated_exec.py"
        if existing_file and Path(existing_file).resolve() == expected.resolve():
            return existing
    path = script_dir / "companion_isolated_exec.py"
    if not path.is_file():
        raise RuntimeError(f"Missing {path}")
    return exec_companion_module(path, "companion_isolated_exec")
