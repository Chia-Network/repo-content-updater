"""Stdlib-only path-scrub + importlib exec (single source for cold-start and loader)."""

from __future__ import annotations

import importlib.util
import sys
import types
from collections.abc import Callable
from pathlib import Path


def _exec_with_path_filter(
    script_dir: Path,
    path: Path,
    module_name: str,
    *,
    register: bool,
    exec_module: Callable[[types.ModuleType], object],
) -> types.ModuleType:
    """Exec module source while script_dir is removed from sys.path."""
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
        exec_module(module)
    finally:
        sys.path[:] = saved_path
    return module


def exec_scripts_dir_module(
    script_dir: Path,
    path: Path,
    module_name: str,
    *,
    register: bool = True,
) -> types.ModuleType:
    """Load a module from script_dir while that directory is removed from sys.path."""
    path = path.resolve()
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {path}")
    loader = spec.loader

    def _run(module: types.ModuleType) -> None:
        loader.exec_module(module)

    return _exec_with_path_filter(
        script_dir, path, module_name, register=register, exec_module=_run
    )
