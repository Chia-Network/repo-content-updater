"""Stdlib-only scripts-dir module loader (single path-scrub + exec primitive)."""

from __future__ import annotations

import types
from pathlib import Path

from scripts_dir_path_scrub import exec_scripts_dir_module


def _exec_scripts_dir_module(
    script_dir: Path,
    path: Path,
    module_name: str,
    *,
    register: bool = True,
) -> types.ModuleType:
    return exec_scripts_dir_module(
        script_dir, path, module_name, register=register
    )


def bootstrap_module_from_scripts_dir(
    script_dir: Path,
    filename: str,
    module_name: str,
) -> types.ModuleType:
    """Load a stdlib-only scripts-dir module with the script directory removed from sys.path."""
    return exec_scripts_dir_module(
        script_dir, script_dir / filename, module_name, register=True
    )


def cold_start_hop_load_self(script_dir: Path) -> types.ModuleType:
    """Cold-start hop: scrub-load scripts_dir_module_loader.py from script_dir."""
    return exec_scripts_dir_module(
        script_dir,
        script_dir / "scripts_dir_module_loader.py",
        "scripts_dir_module_loader",
        register=True,
    )
