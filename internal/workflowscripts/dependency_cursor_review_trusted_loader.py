#!/usr/bin/env python3
"""Workflow entry: load trusted formatter loader via bootstrap canonical API."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

DEFAULT_SCRIPT_CANDIDATES: tuple[Path, ...] = (
    Path(".github/scripts"),
    Path("internal/workflowscripts"),
)


def _load_util(base: Path):
    name = "script_dir_isolated_load"
    path = base / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def resolve_trusted_formatter_loader_module(
    candidate_script_dirs: tuple[Path, ...] = DEFAULT_SCRIPT_CANDIDATES,
):
    """Find script dir and return trusted_formatter_loader module."""
    for script_dir in candidate_script_dirs:
        script_dir = script_dir.resolve()
        bootstrap_path = script_dir / "trusted_formatter_loader_bootstrap.py"
        loader_path = script_dir / "trusted_formatter_loader.py"
        if not bootstrap_path.is_file() or not loader_path.is_file():
            continue
        util = _load_util(script_dir)
        util.load_module_isolated(
            script_dir / "companion_isolated_exec.py", "companion_isolated_exec"
        )
        bootstrap = util.load_module_isolated(
            bootstrap_path, "trusted_formatter_loader_bootstrap"
        )
        return bootstrap.load_trusted_formatter_loader_module(script_dir)
    raise RuntimeError(
        "trusted_formatter_loader.py not found under .github/scripts/. "
        "Run repo-content-updater managed-files for dependency-cursor-review."
    )
