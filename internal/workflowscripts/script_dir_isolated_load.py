"""Stdlib-only: load a module from a file path with its directory scrubbed from sys.path."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
import types
from pathlib import Path

DEFAULT_SCRIPT_CANDIDATES: tuple[Path, ...] = (
    Path(".github/scripts"),
    Path("internal/workflowscripts"),
)


def exec_module_scrubbing_script_dir(
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


def load_module_isolated(
    script_path: Path,
    module_name: str | None = None,
    *,
    register: bool = True,
) -> types.ModuleType:
    """Register and exec a module without leaving its directory on sys.path."""
    script_path = script_path.resolve()
    name = module_name or f"isolated_{script_path.stem}"
    if register:
        existing = sys.modules.get(name)
        if existing is not None:
            existing_file = getattr(existing, "__file__", None)
            if existing_file and Path(existing_file).resolve() == script_path:
                return existing
    spec = importlib.util.spec_from_file_location(name, script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {script_path}")
    module = importlib.util.module_from_spec(spec)
    if register:
        sys.modules[name] = module
    exec_module_scrubbing_script_dir(spec, module, script_path)
    return module


def register_util_from_scripts_dir(script_dir: Path) -> types.ModuleType:
    """Register script_dir_isolated_load from a trusted scripts directory."""
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


def resolve_trusted_formatter_loader_for_dir(script_dir: Path) -> types.ModuleType:
    """Isolated companion + bootstrap + trusted_formatter_loader for one scripts dir."""
    script_dir = script_dir.resolve()
    util = register_util_from_scripts_dir(script_dir)
    util.load_module_isolated(
        script_dir / "companion_isolated_exec.py", "companion_isolated_exec"
    )
    bootstrap = util.load_module_isolated(
        script_dir / "trusted_formatter_loader_bootstrap.py",
        "trusted_formatter_loader_bootstrap",
    )
    loader_path = script_dir / "trusted_formatter_loader.py"
    if not loader_path.is_file():
        raise RuntimeError(f"Missing {loader_path}")
    return bootstrap.load_loader_module(loader_path)


def resolve_trusted_formatter_loader_module(
    candidate_script_dirs: tuple[Path, ...] = DEFAULT_SCRIPT_CANDIDATES,
) -> types.ModuleType:
    """Find a trusted scripts directory and return trusted_formatter_loader."""
    for script_dir in candidate_script_dirs:
        script_dir = script_dir.resolve()
        bootstrap_path = script_dir / "trusted_formatter_loader_bootstrap.py"
        loader_path = script_dir / "trusted_formatter_loader.py"
        util_path = script_dir / "script_dir_isolated_load.py"
        if not (
            util_path.is_file()
            and bootstrap_path.is_file()
            and loader_path.is_file()
        ):
            continue
        return resolve_trusted_formatter_loader_for_dir(script_dir)
    raise RuntimeError(
        "trusted_formatter_loader.py not found under .github/scripts/. "
        "Run repo-content-updater managed-files for dependency-cursor-review."
    )
