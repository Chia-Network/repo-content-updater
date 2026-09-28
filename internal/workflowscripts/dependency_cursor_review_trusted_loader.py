#!/usr/bin/env python3
"""Workflow entry: load trusted formatter loader via canonical cold-start spine."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

DEFAULT_SCRIPT_CANDINATES: tuple[Path, ...] = (
    Path(".github/scripts"),
    Path("internal/workflowscripts"),
)


def _cold_start_module(install_dir: Path | None = None):
    install = (install_dir or Path(__file__).resolve().parent).resolve()
    name = "trusted_formatter_loader_cold_start"
    path = install / f"{name}.py"
    existing = sys.modules.get(name)
    if existing is not None:
        existing_file = getattr(existing, "__file__", None)
        if existing_file and Path(existing_file).resolve() == path.resolve():
            return existing
    if not path.is_file():
        raise RuntimeError(f"Missing {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def resolve_trusted_formatter_loader_module(
    candidate_script_dirs: tuple[Path, ...] = DEFAULT_SCRIPT_CANDINATES,
):
    """Find script dir and return trusted_formatter_loader module."""
    return _cold_start_module().resolve_loader_module(candidate_script_dirs)
