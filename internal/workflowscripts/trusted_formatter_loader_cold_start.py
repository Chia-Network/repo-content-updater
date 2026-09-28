"""Stdlib-only cold start for python3 -I (one scrub hop → resolve_loader_bundle).

Load sequence under python3 -I:
  resolve_loader_bundle → bootstrap scripts_dir_path_scrub (once) → exec loader
  → isolated_module_exec → resolve_trusted_formatter_loader_for_dir → sibling preload.
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

_LOADER = "scripts_dir_module_loader"
_SCRUB = "scripts_dir_path_scrub"
_ISO = "isolated_module_exec"


def _bootstrap_scripts_dir_path_scrub(script_dir: Path) -> types.ModuleType:
    """Chicken-and-egg: load scripts_dir_path_scrub (one inline scrub exec; see path_scrub module)."""
    script_dir = script_dir.resolve()
    scrub_path = script_dir / f"{_SCRUB}.py"
    existing = sys.modules.get(_SCRUB)
    if existing is not None:
        existing_file = getattr(existing, "__file__", None)
        if existing_file and Path(existing_file).resolve() == scrub_path.resolve():
            return existing
    spec = importlib.util.spec_from_file_location(_SCRUB, scrub_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {scrub_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[_SCRUB] = module
    script_dir_s = str(script_dir)
    saved_path = sys.path.copy()
    try:
        sys.path = [entry for entry in sys.path if entry != script_dir_s]
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = saved_path
    return module


def _cold_start_hop_load_scripts_dir_module_loader(script_dir: Path) -> types.ModuleType:
    """Scrub-load scripts_dir_module_loader, then cold_start_hop_load_self."""
    script_dir = script_dir.resolve()
    path = script_dir / f"{_LOADER}.py"
    existing = sys.modules.get(_LOADER)
    if existing is not None:
        existing_file = getattr(existing, "__file__", None)
        if existing_file and Path(existing_file).resolve() == path.resolve():
            return existing.cold_start_hop_load_self(script_dir)
    scrub = _bootstrap_scripts_dir_path_scrub(script_dir)
    module = scrub.exec_scripts_dir_module(script_dir, path, _LOADER)
    return module.cold_start_hop_load_self(script_dir)


def _scripts_dir_module_loader(script_dir: Path) -> types.ModuleType:
    script_dir = script_dir.resolve()
    loader_path = script_dir / f"{_LOADER}.py"
    existing = sys.modules.get(_LOADER)
    if existing is not None:
        existing_file = getattr(existing, "__file__", None)
        if existing_file and Path(existing_file).resolve() == loader_path.resolve():
            return existing
    return _cold_start_hop_load_scripts_dir_module_loader(script_dir)


def _loader_resolve_markers(script_dir: Path) -> tuple[str, ...]:
    bootstrap = _scripts_dir_module_loader(script_dir).bootstrap_module_from_scripts_dir
    bundle = bootstrap(script_dir, "formatter_runtime_bundle.py", "formatter_runtime_bundle")
    return bundle.LOADER_RESOLVE_MARKER_FILENAMES


def resolve_loader_for_dir(script_dir: Path) -> types.ModuleType:
    """Return trusted_formatter_loader via isolated_module_exec resolve spine."""
    script_dir = script_dir.resolve()
    bootstrap = _scripts_dir_module_loader(script_dir).bootstrap_module_from_scripts_dir
    iso = bootstrap(script_dir, f"{_ISO}.py", _ISO)
    iso.register_util_from_scripts_dir(script_dir)
    return iso.resolve_trusted_formatter_loader_for_dir(script_dir)


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
