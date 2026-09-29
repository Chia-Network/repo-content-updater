"""Stdlib-only path-scrub + importlib exec (single bootstrap surface for scripts-dir modules).

Intentional exception: ``load_scrub_from_disk_under_dash_i`` loads ``scripts_dir_path_scrub``
from disk **without** path-filter (via ``scripts_dir_disk_exec``). Every other trusted
module load uses ``bootstrap_module_from_scripts_dir`` / ``exec_scripts_dir_module`` →
``_exec_with_path_filter``.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from collections.abc import Callable
from importlib.abc import Loader
from pathlib import Path

from scripts_dir_disk_exec import exec_trusted_module_from_disk

_SCRUB_MODULE = "scripts_dir_path_scrub"


def cached_trusted_module(module_name: str, path: Path) -> types.ModuleType | None:
    """Return a sys.modules entry when it already points at the resolved trusted path."""
    path = path.resolve()
    existing = sys.modules.get(module_name)
    if existing is None:
        return None
    existing_file = getattr(existing, "__file__", None)
    if existing_file and Path(existing_file).resolve() == path:
        return existing
    return None


def load_scrub_from_disk_under_dash_i(script_dir: Path) -> types.ModuleType:
    """Cold-start owner: exec stdlib-only path_scrub once (no path-filter — see module docstring)."""
    script_dir = script_dir.resolve()
    path = script_dir / f"{_SCRUB_MODULE}.py"
    cached = cached_trusted_module(_SCRUB_MODULE, path)
    if cached is not None:
        return cached
    return exec_trusted_module_from_disk(_SCRUB_MODULE, path)


def _exec_with_path_filter(
    script_dir: Path,
    path: Path,
    module_name: str,
    *,
    register: bool,
    exec_module: Callable[[types.ModuleType, Loader], object],
) -> types.ModuleType:
    """Exec module source while script_dir is removed from sys.path."""
    script_dir = script_dir.resolve()
    path = path.resolve()
    if register:
        cached = cached_trusted_module(module_name, path)
        if cached is not None:
            return cached
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {path}")
    module = importlib.util.module_from_spec(spec)
    if register:
        sys.modules[module_name] = module
    script_dir_s = str(script_dir)
    saved_path = sys.path.copy()
    try:
        sys.path = [entry for entry in sys.path if entry != script_dir_s]
        exec_module(module, spec.loader)
    finally:
        sys.path[:] = saved_path
    return module


def exec_scripts_dir_module(
    script_dir: Path,
    path: Path,
    module_name: str,
    *,
    register: bool = True,
) -> types.ModuleType:
    """Load a module from script_dir while that directory is removed from sys.path."""
    path = path.resolve()

    def _run(module: types.ModuleType, loader: Loader) -> None:
        loader.exec_module(module)

    return _exec_with_path_filter(
        script_dir, path, module_name, register=register, exec_module=_run
    )


def bootstrap_module_from_scripts_dir(
    script_dir: Path,
    filename: str,
    module_name: str,
) -> types.ModuleType:
    """Canonical scripts-dir bootstrap (path-filtered exec)."""
    return exec_scripts_dir_module(
        script_dir, script_dir / filename, module_name, register=True
    )
