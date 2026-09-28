"""Stdlib-only bootstrap for trusted_formatter_loader (workflow one-hop entry)."""

from __future__ import annotations

import sys
import types
from pathlib import Path

_BOOTSTRAP_MODULE_NAME = "trusted_formatter_loader_bootstrap"


def _require_util():
    util = sys.modules.get("script_dir_isolated_load")
    if util is None:
        raise RuntimeError(
            "script_dir_isolated_load must be registered before bootstrap operations"
        )
    return util


def prime_companion_isolated_exec(script_dir: Path) -> types.ModuleType:
    """Load companion_isolated_exec before import-by-name works (python3 -I / scrubbed path)."""
    util = _require_util()
    path = script_dir.resolve() / "companion_isolated_exec.py"
    return util.load_module_isolated(path, "companion_isolated_exec")


def import_bootstrap_module(bootstrap_path: Path) -> types.ModuleType:
    """Load this bootstrap module from disk with scripts-dir isolation."""
    bootstrap_path = bootstrap_path.resolve()
    util = _require_util()
    return util.load_module_isolated(bootstrap_path, _BOOTSTRAP_MODULE_NAME)


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
    return _require_util().load_module_isolated(loader_path, "trusted_formatter_loader")


def exec_companion_module(
    script_path: Path, module_name: str | None = None
) -> types.ModuleType:
    """Re-export for workflow YAML that execs bootstrap then calls exec_companion_module."""
    util = _require_util()
    return util.load_module_isolated(
        script_path.resolve(), module_name or f"companion_{script_path.stem}"
    )
