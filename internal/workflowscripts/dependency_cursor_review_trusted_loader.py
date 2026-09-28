#!/usr/bin/env python3
"""Workflow entry: load trusted formatter loader via canonical resolve API."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

DEFAULT_SCRIPT_CANDIDATES: tuple[Path, ...] = (
    Path(".github/scripts"),
    Path("internal/workflowscripts"),
)


def _util_via_bootstrap(script_dir: Path):
    script_dir = script_dir.resolve()
    boot_name = "trusted_formatter_loader_bootstrap"
    boot_path = script_dir / "trusted_formatter_loader_bootstrap.py"
    boot = sys.modules.get(boot_name)
    if boot is not None:
        boot_file = getattr(boot, "__file__", None)
        if boot_file and Path(boot_file).resolve() == boot_path.resolve():
            return boot.cold_start_util(script_dir)
    if not boot_path.is_file():
        raise RuntimeError(f"Missing {boot_path}")
    spec = importlib.util.spec_from_file_location(boot_name, boot_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {boot_path}")
    boot = importlib.util.module_from_spec(spec)
    sys.modules[boot_name] = boot
    spec.loader.exec_module(boot)
    return boot.cold_start_util(script_dir)


def resolve_trusted_formatter_loader_module(
    candidate_script_dirs: tuple[Path, ...] = DEFAULT_SCRIPT_CANDIDATES,
):
    """Find script dir and return trusted_formatter_loader module."""
    for script_dir in candidate_script_dirs:
        script_dir = script_dir.resolve()
        util_path = script_dir / "script_dir_isolated_load.py"
        bootstrap_path = script_dir / "trusted_formatter_loader_bootstrap.py"
        loader_path = script_dir / "trusted_formatter_loader.py"
        if not (
            util_path.is_file()
            and bootstrap_path.is_file()
            and loader_path.is_file()
        ):
            continue
        util = _util_via_bootstrap(script_dir)
        return util.resolve_trusted_formatter_loader_for_dir(script_dir)
    raise RuntimeError(
        "trusted_formatter_loader.py not found under .github/scripts/. "
        "Run repo-content-updater managed-files for dependency-cursor-review."
    )
