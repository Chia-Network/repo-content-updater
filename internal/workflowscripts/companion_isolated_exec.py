"""Canonical scripts-dir isolation for workflow companion modules (stdlib only)."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
import types
from pathlib import Path


def exec_module_isolated_from_scripts_dir(
    spec: importlib.machinery.ModuleSpec,
    module: types.ModuleType,
    script_path: Path,
) -> None:
    """Run module exec with the script directory removed from sys.path."""
    if spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {script_path}")
    script_dir = str(script_path.resolve().parent)
    saved_path = sys.path.copy()
    try:
        sys.path = [entry for entry in sys.path if entry != script_dir]
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = saved_path


def exec_companion_module(
    script_path: Path,
    module_name: str | None = None,
) -> types.ModuleType:
    """Load a workflow companion module with its directory scrubbed from sys.path."""
    script_path = script_path.resolve()
    name = module_name or f"companion_{script_path.stem}"
    spec = importlib.util.spec_from_file_location(name, script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {script_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    exec_module_isolated_from_scripts_dir(spec, module, script_path)
    return module


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
