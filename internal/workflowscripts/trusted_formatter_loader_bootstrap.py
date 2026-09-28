"""Stdlib-only bootstrap for trusted_formatter_loader (workflow one-hop entry)."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

_BOOTSTRAP_MODULE_NAME = "trusted_formatter_loader_bootstrap"


def _load_script_dir_isolated_util(script_dir: Path):
    """Register script_dir_isolated_load from disk (stdlib-only; safe unisolated exec)."""
    script_dir = script_dir.resolve()
    name = "script_dir_isolated_load"
    path = script_dir / f"{name}.py"
    existing = sys.modules.get(name)
    if existing is not None:
        existing_file = getattr(existing, "__file__", None)
        if existing_file and Path(existing_file).resolve() == path.resolve():
            return existing
    if not path.is_file():
        raise RuntimeError(f"Missing {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def prime_companion_isolated_exec(script_dir: Path) -> types.ModuleType:
    """Load companion_isolated_exec before import-by-name works (python3 -I / scrubbed path)."""
    util = _load_script_dir_isolated_util(script_dir)
    path = script_dir.resolve() / "companion_isolated_exec.py"
    return util.load_module_isolated(path, "companion_isolated_exec")


def _companion_api(script_dir: Path):
    companion = prime_companion_isolated_exec(script_dir)
    return (
        companion.exec_companion_module,
        companion.exec_module_isolated_from_scripts_dir,
    )


def import_bootstrap_module(bootstrap_path: Path) -> types.ModuleType:
    """Load this bootstrap module from disk with scripts-dir isolation."""
    bootstrap_path = bootstrap_path.resolve()
    exec_companion_module, _ = _companion_api(bootstrap_path.parent)
    return exec_companion_module(bootstrap_path, _BOOTSTRAP_MODULE_NAME)


def ensure_bootstrap_module_for_loader(loader_path: Path) -> None:
    """Register trusted_formatter_loader_bootstrap in sys.modules before isolated loader exec."""
    loader_path = loader_path.resolve()
    bootstrap_path = loader_path.parent / "trusted_formatter_loader_bootstrap.py"
    if not bootstrap_path.is_file():
        raise RuntimeError(
            f"Missing {bootstrap_path} beside trusted_formatter_loader.py"
        )
    existing = sys.modules.get(_BOOTSTRAP_MODULE_NAME)
    if existing is not None:
        existing_file = getattr(existing, "__file__", None)
        if existing_file and Path(existing_file).resolve() == bootstrap_path.resolve():
            return
    import_bootstrap_module(bootstrap_path)


def load_loader_module(loader_path: Path) -> types.ModuleType:
    """Load trusted_formatter_loader from disk with scripts-dir isolation."""
    loader_path = loader_path.resolve()
    ensure_bootstrap_module_for_loader(loader_path)
    _, exec_module_isolated_from_scripts_dir = _companion_api(loader_path.parent)
    spec = importlib.util.spec_from_file_location(
        "trusted_formatter_loader", loader_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {loader_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    exec_module_isolated_from_scripts_dir(spec, module, loader_path)
    return module


def load_trusted_formatter_loader_module(script_dir: Path) -> types.ModuleType:
    """Canonical workflow entry: isolated bootstrap + isolated loader."""
    script_dir = script_dir.resolve()
    bootstrap_path = script_dir / "trusted_formatter_loader_bootstrap.py"
    loader_path = script_dir / "trusted_formatter_loader.py"
    if not bootstrap_path.is_file():
        raise RuntimeError(f"Missing {bootstrap_path}")
    if not loader_path.is_file():
        raise RuntimeError(f"Missing {loader_path}")
    import_bootstrap_module(bootstrap_path)
    return load_loader_module(loader_path)


def exec_companion_module(script_path: Path, module_name: str | None = None) -> types.ModuleType:
    """Re-export for workflow YAML that execs bootstrap then calls exec_companion_module."""
    exec_companion_module_fn, _ = _companion_api(script_path.parent)
    return exec_companion_module_fn(script_path, module_name)
