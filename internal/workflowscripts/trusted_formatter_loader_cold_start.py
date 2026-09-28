"""Stdlib-only cold start for python3 -I workflow scripts (single loader resolve spine)."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

DEFAULT_SCRIPT_CANDIDATES: tuple[Path, ...] = (
    Path(".github/scripts"),
    Path("internal/workflowscripts"),
)

_BOOTSTRAP_NAME = "trusted_formatter_loader_bootstrap"
def _exec_bootstrap(script_dir: Path) -> types.ModuleType:
    script_dir = script_dir.resolve()
    boot_path = script_dir / f"{_BOOTSTRAP_NAME}.py"
    boot = sys.modules.get(_BOOTSTRAP_NAME)
    if boot is not None:
        boot_file = getattr(boot, "__file__", None)
        if boot_file and Path(boot_file).resolve() == boot_path.resolve():
            return boot
    if not boot_path.is_file():
        raise RuntimeError(f"Missing {boot_path}")
    spec = importlib.util.spec_from_file_location(_BOOTSTRAP_NAME, boot_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {boot_path}")
    boot = importlib.util.module_from_spec(spec)
    sys.modules[_BOOTSTRAP_NAME] = boot
    script_dir_str = str(script_dir)
    saved_path = sys.path.copy()
    try:
        sys.path = [entry for entry in sys.path if entry != script_dir_str]
        spec.loader.exec_module(boot)
    finally:
        sys.path[:] = saved_path
    return boot


def resolve_loader_for_dir(script_dir: Path) -> types.ModuleType:
    """Return trusted_formatter_loader after one bootstrap → resolve graph."""
    return _exec_bootstrap(script_dir).load_trusted_formatter_loader_module(
        script_dir.resolve()
    )


def resolve_loader_module(
    candidate_script_dirs: tuple[Path, ...] = DEFAULT_SCRIPT_CANDIDATES,
) -> types.ModuleType:
    """Find a trusted scripts directory and return trusted_formatter_loader."""
    for script_dir in candidate_script_dirs:
        script_dir = script_dir.resolve()
        util_path = script_dir / "script_dir_isolated_load.py"
        bootstrap_path = script_dir / f"{_BOOTSTRAP_NAME}.py"
        loader_path = script_dir / "trusted_formatter_loader.py"
        if not (
            util_path.is_file()
            and bootstrap_path.is_file()
            and loader_path.is_file()
        ):
            continue
        return resolve_loader_for_dir(script_dir)
    raise RuntimeError(
        "trusted_formatter_loader.py not found under .github/scripts/. "
        "Run repo-content-updater managed-files for dependency-cursor-review."
    )
