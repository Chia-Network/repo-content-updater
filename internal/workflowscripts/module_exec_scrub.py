"""Stdlib-only sys.path scrub wrapper for isolated module exec."""

from __future__ import annotations

import importlib.machinery
import sys
import types
from pathlib import Path

from module_exec_scrub_bootstrap import bootstrap_module_from_scripts_dir


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


def ensure_module_from_scripts_dir(
    script_dir: Path,
    filename: str,
    module_name: str,
) -> types.ModuleType:
    """Load module_exec_scrub (or bootstrap) via the shared bootstrap spine."""
    return bootstrap_module_from_scripts_dir(script_dir, filename, module_name)
