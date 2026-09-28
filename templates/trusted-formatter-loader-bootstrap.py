"""Stdlib-only bootstrap for trusted_formatter_loader (workflow one-hop entry).

Workflow inline Python loads this module with scripts-dir isolation, then calls
load_loader_module(loader_path) — no separate unisolated exec of the loader entry.
"""

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


def load_loader_module(loader_path: Path) -> types.ModuleType:
    """Load trusted_formatter_loader from disk with scripts-dir isolation."""
    loader_path = loader_path.resolve()
    spec = importlib.util.spec_from_file_location(
        "trusted_formatter_loader", loader_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {loader_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    exec_module_isolated_from_scripts_dir(spec, module, loader_path)
    return module
