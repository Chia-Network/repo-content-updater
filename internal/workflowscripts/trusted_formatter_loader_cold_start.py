"""Stdlib-only cold start for python3 -I workflow scripts (single loader resolve spine).

Load sequence:
  cold_start → hop scripts_dir_module_loader → isolated_module_exec
  → register util → script_dir_isolated_load.resolve_trusted_formatter_loader_for_dir
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
    """Documented sole chicken-and-egg bootstrap site (loads scripts_dir_module_loader.py)."""
    script_dir = script_dir.resolve()
    loader_path = script_dir / f"{_SCRIPTS_DIR_LOADER}.py"
    if not loader_path.is_file():
        raise RuntimeError(f"Missing {loader_path}")
    spec = importlib.util.spec_from_file_location(_SCRIPTS_DIR_LOADER, loader_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {loader_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[_SCRIPTS_DIR_LOADER] = module
    script_dir_s = str(script_dir)
    saved_path = sys.path.copy()
    try:
        sys.path = [entry for entry in sys.path if entry != script_dir_s]
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = saved_path
    return module


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
    loader = _scripts_dir_loader(script_dir)
    spec = importlib.util.spec_from_file_location(_ISO_NAME, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[_ISO_NAME] = module
    loader.exec_module_scrubbing_script_dir(spec, module, path)
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
