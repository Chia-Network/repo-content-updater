"""Load the malware verdict formatter from an explicit file path (no sys.path prepend)."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
import types
from collections.abc import Callable
from pathlib import Path

TRUSTED_FORMATTER_MODULE_NAME = "trusted_malware_verdict_formatter"


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


def import_module_from_trusted_script(
    script_path: Path,
    module_name: str | None = None,
) -> types.ModuleType:
    script_path = script_path.resolve()
    name = module_name or f"trusted_script_{script_path.stem}"
    spec = importlib.util.spec_from_file_location(name, script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {script_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    exec_module_isolated_from_scripts_dir(spec, module, script_path)
    return module


def load_format_malware_review_verdict(script_path: Path) -> Callable[[str], str]:
    module = import_module_from_trusted_script(script_path, TRUSTED_FORMATTER_MODULE_NAME)
    formatter = getattr(module, "format_malware_review_verdict", None)
    if not callable(formatter):
        raise RuntimeError(f"{script_path} missing format_malware_review_verdict")
    return formatter


def find_and_load_format_malware_review_verdict(
    *candidate_dirs: Path,
) -> Callable[[str], str]:
    for script_dir in candidate_dirs:
        script_path = script_dir / "malware_verdict_formatter.py"
        if script_path.is_file():
            return load_format_malware_review_verdict(script_path)
    raise RuntimeError(
        "malware_verdict_formatter.py not found under .github/scripts/. "
        "Run repo-content-updater managed-files for dependency-cursor-review "
        "(config companion_files pull in malware-verdict-formatter and "
        "trusted-formatter-loader automatically) "
        "or use managed-files group:dependency-cursor-review."
    )
