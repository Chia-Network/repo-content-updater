"""Stdlib-only scripts-dir module loader (single path-scrub + exec primitive)."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
import types
from pathlib import Path


def _exec_scripts_dir_module(
    script_dir: Path,
    path: Path,
    module_name: str,
    *,
    register: bool = True,
) -> types.ModuleType:
    script_dir = script_dir.resolve()
    path = path.resolve()
    if register:
        existing = sys.modules.get(module_name)
        if existing is not None:
            existing_file = getattr(existing, "__file__", None)
            if existing_file and Path(existing_file).resolve() == path:
                return existing
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {path}")
    module = importlib.util.module_from_spec(spec)
    if register:
        sys.modules[module_name] = module
    script_dir_s = str(script_dir)
    saved_path = sys.path.copy()
    try:
        sys.path = [entry for entry in sys.path if entry != script_dir_s]
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = saved_path
    return module


def bootstrap_module_from_scripts_dir(
    script_dir: Path,
    filename: str,
    module_name: str,
) -> types.ModuleType:
    """Load a stdlib-only scripts-dir module with the script directory removed from sys.path."""
    return _exec_scripts_dir_module(
        script_dir, script_dir / filename, module_name, register=True
    )


def exec_module_scrubbing_script_dir(
    spec: importlib.machinery.ModuleSpec,
    module: types.ModuleType,
    script_path: Path,
) -> None:
    """Run module exec with the script directory removed from sys.path."""
    if spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {script_path}")
    script_dir = script_path.resolve().parent
    script_dir_s = str(script_dir)
    saved_path = sys.path.copy()
    try:
        sys.path = [entry for entry in sys.path if entry != script_dir_s]
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = saved_path


def cold_start_hop_load_self(script_dir: Path) -> types.ModuleType:
    """Load scripts_dir_module_loader.py from script_dir (used by cold_start hop only)."""
    return _exec_scripts_dir_module(
        script_dir,
        script_dir / "scripts_dir_module_loader.py",
        "scripts_dir_module_loader",
        register=True,
    )
