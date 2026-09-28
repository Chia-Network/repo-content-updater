#!/usr/bin/env python3
"""Canonical workflow entry for trusted formatter loader (stdlib + importlib only).

Loads bootstrap with scripts-dir isolation, then load_trusted_formatter_loader_module.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
import types
from pathlib import Path

DEFAULT_SCRIPT_CANDIDATES: tuple[Path, ...] = (
    Path(".github/scripts"),
    Path("internal/workflowscripts"),
)


def _exec_module_isolated(
    spec: importlib.machinery.ModuleSpec,
    module: types.ModuleType,
    script_path: Path,
) -> None:
    """Mirror bootstrap.exec_module_isolated_from_scripts_dir (stdlib-only; no bootstrap import)."""
    if spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {script_path}")
    script_dir = str(script_path.resolve().parent)
    saved_path = sys.path.copy()
    try:
        sys.path = [entry for entry in sys.path if entry != script_dir]
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = saved_path


def _load_bootstrap_module(bootstrap_path: Path) -> types.ModuleType:
    bootstrap_path = bootstrap_path.resolve()
    spec = importlib.util.spec_from_file_location(
        "trusted_formatter_loader_bootstrap", bootstrap_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {bootstrap_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    _exec_module_isolated(spec, module, bootstrap_path)
    return module


def resolve_trusted_formatter_loader_module(
    candidate_script_dirs: tuple[Path, ...] = DEFAULT_SCRIPT_CANDIDATES,
):
    """Load trusted_formatter_loader via isolated bootstrap + load_trusted_formatter_loader_module."""
    for script_dir in candidate_script_dirs:
        script_dir = script_dir.resolve()
        bootstrap_path = script_dir / "trusted_formatter_loader_bootstrap.py"
        loader_path = script_dir / "trusted_formatter_loader.py"
        if not bootstrap_path.is_file() or not loader_path.is_file():
            continue
        bootstrap = _load_bootstrap_module(bootstrap_path)
        return bootstrap.load_trusted_formatter_loader_module(script_dir)
    raise RuntimeError(
        "trusted_formatter_loader.py not found under .github/scripts/. "
        "Run repo-content-updater managed-files for dependency-cursor-review."
    )
