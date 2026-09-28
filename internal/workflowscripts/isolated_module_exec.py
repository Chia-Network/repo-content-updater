"""Stdlib-only module isolation (scrub script dir from sys.path during exec)."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
import types
from pathlib import Path


def exec_module_scrubbing_script_dir(
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


def load_module_isolated(
    script_path: Path,
    module_name: str | None = None,
    *,
    register: bool = True,
) -> types.ModuleType:
    """Register and exec a module without leaving its directory on sys.path."""
    script_path = script_path.resolve()
    name = module_name or f"isolated_{script_path.stem}"
    if register:
        existing = sys.modules.get(name)
        if existing is not None:
            existing_file = getattr(existing, "__file__", None)
            if existing_file and Path(existing_file).resolve() == script_path:
                return existing
    spec = importlib.util.spec_from_file_location(name, script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {script_path}")
    module = importlib.util.module_from_spec(spec)
    if register:
        sys.modules[name] = module
    exec_module_scrubbing_script_dir(spec, module, script_path)
    return module


def register_util_from_scripts_dir(script_dir: Path) -> types.ModuleType:
    """Register script_dir_isolated_load from a trusted scripts directory."""
    script_dir = script_dir.resolve()
    name = "script_dir_isolated_load"
    path = script_dir / f"{name}.py"
    existing = sys.modules.get(name)
    if existing is not None:
        existing_file = getattr(existing, "__file__", None)
        if existing_file and Path(existing_file).resolve() == path.resolve():
            return existing
    iso_path = script_dir / "isolated_module_exec.py"
    if not iso_path.is_file():
        raise RuntimeError(f"Missing {iso_path}")
    load_module_isolated(iso_path, "isolated_module_exec")
    return load_module_isolated(path, name)
