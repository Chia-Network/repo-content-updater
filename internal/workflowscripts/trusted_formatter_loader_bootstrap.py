"""Stdlib-only bootstrap for trusted_formatter_loader (workflow one-hop entry).

Workflow inline Python loads this module with scripts-dir isolation, then calls
load_loader_module(loader_path) — no separate unisolated exec of the loader entry.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
import types
from pathlib import Path


def exec_companion_module(
    script_path: Path,
    module_name: str | None = None,
) -> types.ModuleType:
    """Load a workflow companion module with its directory scrubbed from sys.path."""
    script_path = script_path.resolve()
    name = module_name or f"companion_{script_path.stem}"
    spec = importlib.util.spec_from_file_location(name, script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {script_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    exec_module_isolated_from_scripts_dir(spec, module, script_path)
    return module


def exec_module_isolated_from_scripts_dir(
    spec: importlib.machinery.ModuleSpec,
    module: types.ModuleType,
    script_path: Path,
) -> None:
    """Run module exec with the script directory removed from sys.path."""
    if spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {script_path}")
    script_dir = str(script_path.resolve().parent)
    saved_path = sys.path.copy()
    try:
        sys.path = [entry for entry in sys.path if entry != script_dir]
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = saved_path


_BOOTSTRAP_MODULE_NAME = "trusted_formatter_loader_bootstrap"


def ensure_bootstrap_module_for_loader(loader_path: Path) -> None:
    """Register trusted_formatter_loader_bootstrap in sys.modules before isolated loader exec.

    The loader imports bootstrap by name; with the scripts directory scrubbed from sys.path
    that import only succeeds when bootstrap is already in sys.modules.
    """
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
    spec = importlib.util.spec_from_file_location(
        "trusted_formatter_loader", loader_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {loader_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    exec_module_isolated_from_scripts_dir(spec, module, loader_path)
    return module


def import_bootstrap_module(bootstrap_path: Path) -> types.ModuleType:
    """Load this bootstrap module from disk with scripts-dir isolation."""
    bootstrap_path = bootstrap_path.resolve()
    spec = importlib.util.spec_from_file_location(
        "trusted_formatter_loader_bootstrap", bootstrap_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {bootstrap_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    exec_module_isolated_from_scripts_dir(spec, module, bootstrap_path)
    return module


def resolve_trusted_formatter_loader_module(
    *candidate_script_dirs: Path,
) -> types.ModuleType:
    """Load trusted_formatter_loader from the first scripts dir that has the bundle."""
    for script_dir in candidate_script_dirs:
        script_dir = script_dir.resolve()
        bootstrap_path = script_dir / "trusted_formatter_loader_bootstrap.py"
        loader_path = script_dir / "trusted_formatter_loader.py"
        if bootstrap_path.is_file() and loader_path.is_file():
            return load_trusted_formatter_loader_module(script_dir)
    raise RuntimeError(
        "trusted_formatter_loader.py not found under .github/scripts/. "
        "Run repo-content-updater managed-files for dependency-cursor-review."
    )


def load_trusted_formatter_loader_module(script_dir: Path) -> types.ModuleType:
    """Single workflow entry: isolated bootstrap + isolated loader (stdlib-only YAML may exec bootstrap unisolated then call this)."""
    script_dir = script_dir.resolve()
    bootstrap_path = script_dir / "trusted_formatter_loader_bootstrap.py"
    loader_path = script_dir / "trusted_formatter_loader.py"
    if not bootstrap_path.is_file():
        raise RuntimeError(f"Missing {bootstrap_path}")
    if not loader_path.is_file():
        raise RuntimeError(f"Missing {loader_path}")
    import_bootstrap_module(bootstrap_path)
    return load_loader_module(loader_path)
