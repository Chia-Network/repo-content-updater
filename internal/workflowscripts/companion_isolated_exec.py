"""Managed-files deploy name for script_dir_isolated_load isolation entrypoints."""

from __future__ import annotations

import sys
from pathlib import Path


def exec_module_isolated_from_scripts_dir(spec, module, script_path: Path) -> None:
    sys.modules["script_dir_isolated_load"].exec_module_scrubbing_script_dir(
        spec, module, script_path
    )


def exec_companion_module(script_path: Path, module_name: str | None = None):
    util = sys.modules["script_dir_isolated_load"]
    script_path = script_path.resolve()
    name = module_name or f"companion_{script_path.stem}"
    return util.load_module_isolated(script_path, name)


def ensure_companion_isolated_exec(script_dir: Path):
    script_dir = script_dir.resolve()
    existing = sys.modules.get("companion_isolated_exec")
    expected = script_dir / "companion_isolated_exec.py"
    if existing is not None:
        existing_file = getattr(existing, "__file__", None)
        if existing_file and Path(existing_file).resolve() == expected.resolve():
            return existing
    return exec_companion_module(expected, "companion_isolated_exec")
