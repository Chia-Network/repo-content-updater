"""Stdlib-only scripts-dir module loader (delegates to scripts_dir_path_scrub)."""

from __future__ import annotations

import types
from pathlib import Path

from scripts_dir_path_scrub import exec_scripts_dir_module


def bootstrap_module_from_scripts_dir(
    script_dir: Path,
    filename: str,
    module_name: str,
) -> types.ModuleType:
    """Canonical scripts-dir bootstrap (delegates to scripts_dir_path_scrub.exec_scripts_dir_module)."""
    return exec_scripts_dir_module(
        script_dir, script_dir / filename, module_name, register=True
    )
