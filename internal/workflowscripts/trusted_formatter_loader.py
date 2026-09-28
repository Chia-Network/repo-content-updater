"""Load the malware verdict formatter from an explicit file path (no sys.path prepend)."""

from __future__ import annotations

import importlib.util
import sys
import types
from collections.abc import Callable
from pathlib import Path

TRUSTED_FORMATTER_MODULE_NAME = "trusted_malware_verdict_formatter"

FORMATTER_SIBLING_MODULE_STEMS = (
    "script_dir_isolated_load",
    "companion_isolated_exec",
    "malware_verdict_patterns",
    "malware_verdict_policy_types",
    "malware_verdict_policy_select",
    "malware_verdict_policy_strip",
    "malware_verdict_policy_analysis",
    "malware_verdict_policy",
)

_FORMATTER_ENV_PRIMED: set[Path] = set()


def _util(script_dir: Path):
    parent = script_dir.resolve()
    boot_name = "trusted_formatter_loader_bootstrap"
    boot_path = parent / "trusted_formatter_loader_bootstrap.py"
    boot = sys.modules.get(boot_name)
    if boot is not None:
        boot_file = getattr(boot, "__file__", None)
        if boot_file and Path(boot_file).resolve() == boot_path.resolve():
            return boot.cold_start_util(parent)
    if not boot_path.is_file():
        raise RuntimeError(f"Missing {boot_path}")
    spec = importlib.util.spec_from_file_location(boot_name, boot_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {boot_path}")
    boot = importlib.util.module_from_spec(spec)
    sys.modules[boot_name] = boot
    spec.loader.exec_module(boot)
    return boot.cold_start_util(parent)


def import_module_from_trusted_script(
    script_path: Path,
    module_name: str | None = None,
) -> types.ModuleType:
    script_path = script_path.resolve()
    name = module_name or f"trusted_script_{script_path.stem}"
    util = _util(script_path.parent)
    return util.load_module_isolated(script_path, name)


def ensure_formatter_sibling_modules(script_dir: Path) -> None:
    """Load co-located formatter modules with scripts-dir isolation."""
    parent = script_dir.resolve()
    _util(parent)
    for stem in FORMATTER_SIBLING_MODULE_STEMS:
        mod_name = stem
        existing = sys.modules.get(mod_name)
        if existing is not None:
            existing_path = getattr(existing, "__file__", None)
            if existing_path and Path(existing_path).resolve().parent == parent:
                continue
        path = parent / f"{stem}.py"
        if not path.is_file():
            continue
        import_module_from_trusted_script(path, mod_name)


def prime_formatter_environment(script_dir: Path) -> None:
    """Load formatter sibling modules once per trusted scripts directory."""
    parent = script_dir.resolve()
    if parent in _FORMATTER_ENV_PRIMED:
        return
    util = _util(parent)
    bootstrap_path = parent / "trusted_formatter_loader_bootstrap.py"
    existing = sys.modules.get("trusted_formatter_loader_bootstrap")
    if existing is not None:
        existing_file = getattr(existing, "__file__", None)
        if not existing_file or Path(existing_file).resolve().parent != parent:
            del sys.modules["trusted_formatter_loader_bootstrap"]
            existing = None
    if existing is None:
        util.load_module_isolated(bootstrap_path, "trusted_formatter_loader_bootstrap")
    bootstrap = sys.modules["trusted_formatter_loader_bootstrap"]
    ensure_formatter_sibling_modules(parent)
    bootstrap.load_trusted_formatter_loader_module(parent)
    _FORMATTER_ENV_PRIMED.add(parent)


def load_format_malware_review_verdict(script_path: Path) -> Callable[[str], str]:
    """Return format_malware_review_verdict loaded from an explicit trusted file path."""
    script_path = script_path.resolve()
    prime_formatter_environment(script_path.parent)
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
