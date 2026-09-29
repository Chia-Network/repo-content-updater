"""Stdlib-only cold start for python3 -I (resolve_loader_bundle public entry).

Load sequence under python3 -I:
  1. prime scripts_dir_path_scrub (stdlib-only disk exec — see path_scrub module docstring)
  2. bootstrap sibling modules via path_scrub.bootstrap_module_from_scripts_dir
  3. isolated_module_exec → resolve_trusted_formatter_loader_for_dir → sibling preload
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

_SCRUB = "scripts_dir_path_scrub"
_ISO = "isolated_module_exec"


def _prime_path_scrub(script_dir: Path) -> types.ModuleType:
    """Chicken-and-egg: exec path_scrub from disk before it is importable under python3 -I."""
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
    spec.loader.exec_module(module)
    return module


def bootstrap_scripts_dir_path_scrub(script_dir: Path) -> types.ModuleType:
    """Cold-start entry; delegates to path_scrub.bootstrap_scripts_dir_path_scrub after prime."""
    scrub = _prime_path_scrub(script_dir)
    return scrub.bootstrap_scripts_dir_path_scrub(script_dir)


def _require_scrub(script_dir: Path) -> types.ModuleType:
    return bootstrap_scripts_dir_path_scrub(script_dir)


def _loader_resolve_markers(script_dir: Path) -> tuple[str, ...]:
    scrub = _require_scrub(script_dir)
    bundle = scrub.bootstrap_module_from_scripts_dir(
        script_dir, "formatter_runtime_bundle.py", "formatter_runtime_bundle"
    )
    return bundle.LOADER_RESOLVE_MARKER_FILENAMES


def resolve_loader_for_dir(script_dir: Path) -> types.ModuleType:
    """Return trusted_formatter_loader via isolated_module_exec resolve spine."""
    script_dir = script_dir.resolve()
    scrub = _require_scrub(script_dir)
    iso = scrub.bootstrap_module_from_scripts_dir(script_dir, f"{_ISO}.py", _ISO)
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
