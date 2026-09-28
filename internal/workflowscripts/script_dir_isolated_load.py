"""Stdlib-only: load a module from a file path with its directory scrubbed from sys.path."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path


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
    script_dir = str(script_path.parent)
    saved_path = sys.path.copy()
    try:
        sys.path = [entry for entry in sys.path if entry != script_dir]
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = saved_path
    return module
