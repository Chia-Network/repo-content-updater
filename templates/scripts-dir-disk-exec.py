"""Stdlib-only trusted module disk exec (shared by path_scrub cold-load and cold_start)."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path


def exec_trusted_module_from_disk(module_name: str, module_path: Path) -> types.ModuleType:
    """Exec a module from disk without path-filter (stdlib-only sources only)."""
    module_path = module_path.resolve()
    existing = sys.modules.get(module_name)
    if existing is not None:
        existing_file = getattr(existing, "__file__", None)
        if existing_file and Path(existing_file).resolve() == module_path:
            return existing
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module
