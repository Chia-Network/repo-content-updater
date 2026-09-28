#!/usr/bin/env python3
"""Canonical workflow entry for trusted formatter loader (stdlib + importlib only).

Loads bootstrap with scripts-dir isolation, then load_trusted_formatter_loader_module.
"""

from __future__ import annotations

from pathlib import Path

DEFAULT_SCRIPT_CANDIDATES: tuple[Path, ...] = (
    Path(".github/scripts"),
    Path("internal/workflowscripts"),
)


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
        from companion_isolated_exec import ensure_companion_isolated_exec, exec_companion_module

        ensure_companion_isolated_exec(script_dir)
        bootstrap = exec_companion_module(bootstrap_path, "trusted_formatter_loader_bootstrap")
        return bootstrap.load_trusted_formatter_loader_module(script_dir)
    raise RuntimeError(
        "trusted_formatter_loader.py not found under .github/scripts/. "
        "Run repo-content-updater managed-files for dependency-cursor-review."
    )
