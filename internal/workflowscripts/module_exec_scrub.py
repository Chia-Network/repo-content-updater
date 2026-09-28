"""Stdlib-only sys.path scrub wrapper for isolated module exec."""

from __future__ import annotations

import importlib.machinery
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


def bootstrap_module_from_scripts_dir(
    script_dir: Path,
    filename: str,
    module_name: str,
) -> types.ModuleType:
    """Load a stdlib-only scripts-dir module with a one-time path scrub bootstrap."""
    script_dir = script_dir.resolve()
    path = script_dir / filename
    existing = sys.modules.get(module_name)
    if existing is not None:
        existing_file = getattr(existing, "__file__", None)
        if existing_file and Path(existing_file).resolve() == path.resolve():
            return existing
    import importlib.util

    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    script_dir_s = str(script_dir)
    saved_path = sys.path.copy()
    try:
        sys.path = [entry for entry in sys.path if entry != script_dir_s]
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = saved_path
    return module
