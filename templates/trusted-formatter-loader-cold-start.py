"""Stdlib-only cold start for python3 -I workflow scripts (single loader resolve spine)."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

DEFAULT_SCRIPT_CANDIDATES: tuple[Path, ...] = (
    Path(".github/scripts"),
    Path("internal/workflowscripts"),
)

_ISO_NAME = "isolated_module_exec"
_UTIL_NAME = "script_dir_isolated_load"
_BUNDLE_MARKERS = (
    "isolated_module_exec.py",
    "script_dir_isolated_load.py",
    "trusted_formatter_loader_bootstrap.py",
    "trusted_formatter_loader.py",
)


def _ensure_isolated_module_exec(script_dir: Path) -> types.ModuleType:
    """Load stdlib-only isolation helper (safe unscrubbed exec)."""
    script_dir = script_dir.resolve()
    path = script_dir / f"{_ISO_NAME}.py"
    existing = sys.modules.get(_ISO_NAME)
    if existing is not None:
        existing_file = getattr(existing, "__file__", None)
        if existing_file and Path(existing_file).resolve() == path.resolve():
            return existing
    if not path.is_file():
        raise RuntimeError(f"Missing {path}")
    spec = importlib.util.spec_from_file_location(_ISO_NAME, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[_ISO_NAME] = module
    spec.loader.exec_module(module)
    return module


def _registered_util(script_dir: Path) -> types.ModuleType:
    """Single registration path via isolated_module_exec.register_util_from_scripts_dir."""
    iso = _ensure_isolated_module_exec(script_dir)
    return iso.register_util_from_scripts_dir(script_dir.resolve())


def resolve_loader_for_dir(script_dir: Path) -> types.ModuleType:
    """Return trusted_formatter_loader via script_dir_isolated_load (isolated graph)."""
    util = _registered_util(script_dir)
    return util.resolve_trusted_formatter_loader_for_dir(script_dir.resolve())


def resolve_loader_bundle(
    candidate_script_dirs: tuple[Path, ...] = DEFAULT_SCRIPT_CANDIDATES,
) -> tuple[types.ModuleType, Path]:
    """Find scripts dir; return (trusted_formatter_loader module, chosen directory)."""
    for script_dir in candidate_script_dirs:
        script_dir = script_dir.resolve()
        if not all((script_dir / name).is_file() for name in _BUNDLE_MARKERS):
            continue
        return resolve_loader_for_dir(script_dir), script_dir
    raise RuntimeError(
        "trusted_formatter_loader.py not found under .github/scripts/. "
        "Run repo-content-updater managed-files for dependency-cursor-review."
    )
