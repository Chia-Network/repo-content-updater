"""Stdlib-only cold start for python3 -I (resolve_loader_bundle public entry).

Load sequence under python3 -I:
  1. Minimal chicken-egg bootstrap of ``scripts_dir_disk_exec`` only
  2. ``_require_scrub`` → ``disk.exec_trusted_module_from_disk`` (same as load_scrub)
  3. bootstrap siblings via ``path_scrub.bootstrap_module_from_scripts_dir``
  4. isolated_module_exec → resolve_trusted_formatter_loader_for_dir → sibling preload
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
_DISK_EXEC = "scripts_dir_disk_exec"
_ISO = "isolated_module_exec"

# Keep in sync with formatter_runtime_bundle.LOADER_RESOLVE_MARKER_FILENAMES (tested).
LOADER_RESOLVE_MARKER_FILENAMES: tuple[str, ...] = (
    "isolated_module_exec.py",
    "trusted_formatter_loader.py",
)


def _bootstrap_disk_exec(script_dir: Path) -> types.ModuleType:
    """Minimal chicken-egg: load scripts_dir_disk_exec without any sibling imports."""
    script_dir = script_dir.resolve()
    path = script_dir / f"{_DISK_EXEC}.py"
    existing = sys.modules.get(_DISK_EXEC)
    if existing is not None:
        existing_file = getattr(existing, "__file__", None)
        if existing_file and Path(existing_file).resolve() == path.resolve():
            return existing
    spec = importlib.util.spec_from_file_location(_DISK_EXEC, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[_DISK_EXEC] = module
    spec.loader.exec_module(module)
    return module


def _require_scrub(script_dir: Path) -> types.ModuleType:
    """Return primed path_scrub at the trusted path (single no-filter exec)."""
    script_dir = script_dir.resolve()
    disk = _bootstrap_disk_exec(script_dir)
    scrub_path = script_dir / f"{_SCRUB}.py"
    cached = disk.cached_trusted_module(_SCRUB, scrub_path)
    if cached is not None:
        return cached
    scrub = disk.exec_trusted_module_from_disk(_SCRUB, scrub_path)
    registered = disk.cached_trusted_module(_SCRUB, scrub_path)
    return registered if registered is not None else scrub


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
        if not all((script_dir / name).is_file() for name in LOADER_RESOLVE_MARKER_FILENAMES):
            continue
        return resolve_loader_for_dir(script_dir), script_dir
    raise RuntimeError(
        "trusted_formatter_loader.py not found under .github/scripts/. "
        "Run repo-content-updater managed-files for dependency-cursor-review."
    )
