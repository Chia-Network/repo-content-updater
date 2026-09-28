"""Stdlib-only module isolation and trusted formatter loader resolve spine."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

_SCRUB = "scripts_dir_path_scrub"
_LOADER = "scripts_dir_module_loader"


def _bootstrap_scripts_dir_path_scrub(script_dir: Path) -> types.ModuleType:
    """Load scripts_dir_path_scrub (one inline scrub exec; same as cold_start bootstrap)."""
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


def _ensure_loader_spine(script_dir: Path) -> types.ModuleType:
    script_dir = script_dir.resolve()
    _bootstrap_scripts_dir_path_scrub(script_dir)
    scrub = sys.modules[_SCRUB]
    loader = sys.modules.get(_LOADER)
    loader_path = script_dir / f"{_LOADER}.py"
    if loader is not None:
        existing_file = getattr(loader, "__file__", None)
        if existing_file and Path(existing_file).resolve() == loader_path.resolve():
            return loader
    return scrub.exec_scripts_dir_module(script_dir, loader_path, _LOADER)


def bootstrap_module_from_scripts_dir(
    script_dir: Path,
    filename: str,
    module_name: str,
) -> types.ModuleType:
    """Load a stdlib-only scripts-dir module with the script directory removed from sys.path."""
    loader = _ensure_loader_spine(script_dir)
    return loader.bootstrap_module_from_scripts_dir(script_dir, filename, module_name)


def load_module_isolated(
    script_path: Path,
    module_name: str | None = None,
) -> types.ModuleType:
    """Register and exec a module without leaving its directory on sys.path."""
    script_path = script_path.resolve()
    name = module_name or f"isolated_{script_path.stem}"
    existing = sys.modules.get(name)
    if existing is not None:
        existing_file = getattr(existing, "__file__", None)
        if existing_file and Path(existing_file).resolve() == script_path:
            return existing
    return bootstrap_module_from_scripts_dir(script_path.parent, script_path.name, name)


def register_util_from_scripts_dir(script_dir: Path) -> types.ModuleType:
    """Prime scripts_dir_path_scrub + loader + isolated_module_exec."""
    script_dir = script_dir.resolve()
    name = "isolated_module_exec"
    path = script_dir / f"{name}.py"
    existing = sys.modules.get(name)
    if existing is not None:
        existing_file = getattr(existing, "__file__", None)
        if existing_file and Path(existing_file).resolve() == path.resolve():
            return existing
    _ensure_loader_spine(script_dir)
    if not path.is_file():
        raise RuntimeError(f"Missing {path}")
    return load_module_isolated(path, name)


def resolve_trusted_formatter_loader_for_dir(script_dir: Path) -> types.ModuleType:
    """Load trusted_formatter_loader + formatter policy siblings (scripts-dir isolation)."""
    script_dir = script_dir.resolve()
    util = sys.modules.get("isolated_module_exec")
    if util is None:
        raise RuntimeError(
            "isolated_module_exec must be registered before resolve_trusted_formatter_loader_for_dir"
        )
    util.load_module_isolated(
        script_dir / "formatter_runtime_bundle.py",
        "formatter_runtime_bundle",
    )
    loader_path = script_dir / "trusted_formatter_loader.py"
    if not loader_path.is_file():
        raise RuntimeError(f"Missing {loader_path}")
    loader_mod = util.load_module_isolated(loader_path, "trusted_formatter_loader")
    loader_mod.ensure_formatter_sibling_modules(script_dir)
    return loader_mod
