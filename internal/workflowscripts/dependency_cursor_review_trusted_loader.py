#!/usr/bin/env python3
"""Canonical workflow entry for trusted formatter loader (stdlib + importlib only).

Single place for stdlib-only bootstrap exec before resolve_trusted_formatter_loader_module.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

DEFAULT_SCRIPT_CANDIDATES: tuple[Path, ...] = (
    Path(".github/scripts"),
    Path("internal/workflowscripts"),
)


def resolve_trusted_formatter_loader_module(
    candidate_script_dirs: tuple[Path, ...] = DEFAULT_SCRIPT_CANDIDATES,
):
    """Load trusted_formatter_loader via bootstrap.resolve → load_trusted_formatter_loader_module."""
    for script_dir in candidate_script_dirs:
        bootstrap_path = script_dir / "trusted_formatter_loader_bootstrap.py"
        if not bootstrap_path.is_file():
            continue
        spec = importlib.util.spec_from_file_location(
            "trusted_formatter_loader_bootstrap", bootstrap_path
        )
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Could not load module spec from {bootstrap_path}")
        bootstrap = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = bootstrap
        spec.loader.exec_module(bootstrap)
        return bootstrap.resolve_trusted_formatter_loader_module(*candidate_script_dirs)
    raise RuntimeError(
        "trusted_formatter_loader.py not found under .github/scripts/. "
        "Run repo-content-updater managed-files for dependency-cursor-review."
    )
