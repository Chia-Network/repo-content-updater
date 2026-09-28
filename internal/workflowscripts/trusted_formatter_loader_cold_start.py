"""Stdlib-only cold start for python3 -I workflow scripts (single loader resolve spine).

Load sequence:
  cold_start → hop scripts_dir_module_loader.cold_start_hop_load_self
  → isolated_module_exec → register util → resolve_trusted_formatter_loader_for_dir
  → sibling preload (formatter policy stack).
"""

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
_SCRIPTS_DIR_LOADER = "scripts_dir_module_loader"


def _cold_start_hop_load_scripts_dir_module_loader(script_dir: Path) -> types.ModuleType:
    """Chicken-and-egg hop: scrub-load loader from script_dir, then cold_start_hop_load_self.

    python3 -I does not put the scripts directory on sys.path, so this is the one site that
    inlines the same scrub+exec algorithm as scripts_dir_module_loader._exec_scripts_dir_module
    before the loader module can be imported by name.
    """
    script_dir = script_dir.resolve()
    path = script_dir / f"{_SCRIPTS_DIR_LOADER}.py"
    existing = sys.modules.get(_SCRIPTS_DIR_LOADER)
    if existing is not None:
        existing_file = getattr(existing, "__file__", None)
        if existing_file and Path(existing_file).resolve() == path.resolve():
            return existing.cold_start_hop_load_self(script_dir)
    spec = importlib.util.spec_from_file_location(_SCRIPTS_DIR_LOADER, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[_SCRIPTS_DIR_LOADER] = module
    script_dir_s = str(script_dir)
    saved_path = sys.path.copy()
    try:
        sys.path = [entry for entry in sys.path if entry != script_dir_s]
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = saved_path
    return module.cold_start_hop_load_self(script_dir)


def _scripts_dir_loader(script_dir: Path) -> types.ModuleType:
    script_dir = script_dir.resolve()
    existing = sys.modules.get(_SCRIPTS_DIR_LOADER)
    loader_path = script_dir / f"{_SCRIPTS_DIR_LOADER}.py"
    if existing is not None:
        existing_file = getattr(existing, "__file__", None)
        if existing_file and Path(existing_file).resolve() == loader_path.resolve():
            return existing
    return _cold_start_hop_load_scripts_dir_module_loader(script_dir)


def _bootstrap_spine(script_dir: Path):
    return _scripts_dir_loader(script_dir).bootstrap_module_from_scripts_dir


def _loader_resolve_markers(script_dir: Path) -> tuple[str, ...]:
    bundle = _bootstrap_spine(script_dir)(
        script_dir, "formatter_runtime_bundle.py", "formatter_runtime_bundle"
    )
    return bundle.LOADER_RESOLVE_MARKER_FILENAMES


def _ensure_isolated_module_exec(script_dir: Path) -> types.ModuleType:
    """Load stdlib-only isolation helper via shared scrub spine."""
    script_dir = script_dir.resolve()
    path = script_dir / f"{_ISO_NAME}.py"
    existing = sys.modules.get(_ISO_NAME)
    if existing is not None:
        existing_file = getattr(existing, "__file__", None)
        if existing_file and Path(existing_file).resolve() == path.resolve():
            return existing
    if not path.is_file():
        raise RuntimeError(f"Missing {path}")
    return _bootstrap_spine(script_dir)(script_dir, f"{_ISO_NAME}.py", _ISO_NAME)


def _registered_util(script_dir: Path) -> types.ModuleType:
    """Register script_dir_isolated_load once (isolated_module_exec.register_util_from_scripts_dir)."""
    iso = _ensure_isolated_module_exec(script_dir)
    return iso.register_util_from_scripts_dir(script_dir.resolve())


def resolve_loader_for_dir(script_dir: Path) -> types.ModuleType:
    """Return trusted_formatter_loader via isolated_module_exec resolve spine."""
    util = _registered_util(script_dir)
    return util.resolve_trusted_formatter_loader_for_dir(script_dir.resolve())


def resolve_loader_bundle(
    candidate_script_dirs: tuple[Path, ...] = DEFAULT_SCRIPT_CANDIDATES,
) -> tuple[types.ModuleType, Path]:
    """Find scripts dir; return (trusted_formatter_loader module, chosen directory)."""
    for script_dir in candidate_script_dirs:
        script_dir = script_dir.resolve()
        try:
            markers = _loader_resolve_markers(script_dir)
        except (RuntimeError, OSError):
            continue
        if not all((script_dir / name).is_file() for name in markers):
            continue
        return resolve_loader_for_dir(script_dir), script_dir
    raise RuntimeError(
        "trusted_formatter_loader.py not found under .github/scripts/. "
        "Run repo-content-updater managed-files for dependency-cursor-review."
    )
