"""Stdlib-only cold start for python3 -I (resolve_loader_bundle public entry).

Spine: disk_exec → scrub (``load_scrub_from_disk_under_dash_i``) → path-filtered iso/loader.
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

# Contract: must equal formatter_runtime_bundle.LOADER_RESOLVE_MARKER_FILENAMES (equality-tested).
LOADER_RESOLVE_MARKER_FILENAMES: tuple[str, ...] = (
    "isolated_module_exec.py",
    "trusted_formatter_loader.py",
)


def _bootstrap_disk_exec(script_dir: Path) -> types.ModuleType:
    """Chicken-egg entry; bootstrap body lives in disk_exec.bootstrap_disk_exec_from_script_dir."""
    script_dir = script_dir.resolve()
    mod = sys.modules.get(_DISK_EXEC)
    if mod is not None:
        return mod.bootstrap_disk_exec_from_script_dir(script_dir)
    path = script_dir / f"{_DISK_EXEC}.py"
    spec = importlib.util.spec_from_file_location(_DISK_EXEC, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[_DISK_EXEC] = module
    spec.loader.exec_module(module)
    return module.bootstrap_disk_exec_from_script_dir(script_dir)


def _require_scrub(script_dir: Path) -> types.ModuleType:
    """Return primed path_scrub; cold_start must not call load_scrub before scrub is registered."""
    script_dir = script_dir.resolve()
    disk = _bootstrap_disk_exec(script_dir)
    scrub_path = script_dir / f"{_SCRUB}.py"
    cached = disk.cached_trusted_module(_SCRUB, scrub_path)
    if cached is not None:
        return cached
    disk.exec_trusted_module_from_disk(_SCRUB, scrub_path)
    return getattr(sys.modules[_SCRUB], "load_scrub_from_disk_under_dash_i")(script_dir)


def resolve_loader_for_dir(script_dir: Path) -> types.ModuleType:
    script_dir = script_dir.resolve()
    scrub = _require_scrub(script_dir)
    iso = scrub.bootstrap_module_from_scripts_dir(script_dir, f"{_ISO}.py", _ISO)
    iso.register_util_from_scripts_dir(script_dir)
    return iso.resolve_trusted_formatter_loader_for_dir(script_dir)


def resolve_loader_bundle(
    candidate_script_dirs: tuple[Path, ...] = DEFAULT_SCRIPT_CANDIDATES,
) -> tuple[types.ModuleType, Path]:
    for script_dir in candidate_script_dirs:
        script_dir = script_dir.resolve()
        if not all((script_dir / name).is_file() for name in LOADER_RESOLVE_MARKER_FILENAMES):
            continue
        return resolve_loader_for_dir(script_dir), script_dir
    raise RuntimeError(
        "trusted_formatter_loader.py not found under .github/scripts/. "
        "Run repo-content-updater managed-files for dependency-cursor-review."
    )
