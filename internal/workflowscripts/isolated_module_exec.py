"""Stdlib-only module isolation and trusted formatter loader resolve spine.

``scripts_dir_module_loader.bootstrap_module_from_scripts_dir`` is the canonical
one-liner bootstrap. ``bootstrap_module_from_scripts_dir`` here is the cold-start-aware
façade (requires primed ``scripts_dir_path_scrub`` via ``_bootstrap_via_spine``).
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

_SCRUB = "scripts_dir_path_scrub"
_LOADER = "scripts_dir_module_loader"


def _require_scripts_dir_path_scrub(script_dir: Path) -> types.ModuleType:
    """Require cold-start bootstrap; isolated exec does not duplicate scrub bootstrap."""
    script_dir = script_dir.resolve()
    scrub = sys.modules.get(_SCRUB)
    scrub_path = script_dir / f"{_SCRUB}.py"
    if scrub is None:
        raise RuntimeError(
            "scripts_dir_path_scrub must be primed before isolated_module_exec "
            "(trusted_formatter_loader_cold_start bootstrap under python3 -I)"
        )
    existing_file = getattr(scrub, "__file__", None)
    if not existing_file or Path(existing_file).resolve() != scrub_path.resolve():
        raise RuntimeError(
            f"scripts_dir_path_scrub in sys.modules is not the trusted copy from {scrub_path}"
        )
    return scrub


def _ensure_loader_spine(script_dir: Path) -> types.ModuleType:
    script_dir = script_dir.resolve()
    scrub = _require_scripts_dir_path_scrub(script_dir)
    loader = sys.modules.get(_LOADER)
    loader_path = script_dir / f"{_LOADER}.py"
    if loader is not None:
        existing_file = getattr(loader, "__file__", None)
        if existing_file and Path(existing_file).resolve() == loader_path.resolve():
            return loader
    return scrub.exec_scripts_dir_module(script_dir, loader_path, _LOADER)


def _bootstrap_via_spine(
    script_dir: Path,
    filename: str,
    module_name: str,
) -> types.ModuleType:
    """Cold-start-aware load: require primed path_scrub, then delegate to canonical loader."""
    loader = _ensure_loader_spine(script_dir)
    return loader.bootstrap_module_from_scripts_dir(script_dir, filename, module_name)


def bootstrap_module_from_scripts_dir(
    script_dir: Path,
    filename: str,
    module_name: str,
) -> types.ModuleType:
    """Façade for isolated exec; canonical one-liner lives on scripts_dir_module_loader."""
    return _bootstrap_via_spine(script_dir, filename, module_name)


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
    return _bootstrap_via_spine(script_path.parent, script_path.name, name)


def register_util_from_scripts_dir(script_dir: Path) -> types.ModuleType:
    """Prime loader spine + isolated_module_exec (requires path_scrub already bootstrapped)."""
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
