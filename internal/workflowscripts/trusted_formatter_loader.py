"""Load the malware verdict formatter from an explicit file path (no sys.path prepend)."""

from __future__ import annotations

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


def _load_script_dir_isolated_util(script_dir: Path):
    import importlib.util

    script_dir = script_dir.resolve()
    name = "script_dir_isolated_load"
    path = script_dir / f"{name}.py"
    existing = sys.modules.get(name)
    if existing is not None:
        existing_file = getattr(existing, "__file__", None)
        if existing_file and Path(existing_file).resolve() == path.resolve():
            return existing
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Missing or invalid {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _companion_api(script_dir: Path):
    util = _load_script_dir_isolated_util(script_dir)
    companion_path = script_dir.resolve() / "companion_isolated_exec.py"
    companion = util.load_module_isolated(companion_path, "companion_isolated_exec")
    return (
        companion.exec_companion_module,
        companion.exec_module_isolated_from_scripts_dir,
    )


def import_module_from_trusted_script(
    script_path: Path,
    module_name: str | None = None,
) -> types.ModuleType:
    import importlib.util

    script_path = script_path.resolve()
    name = module_name or f"trusted_script_{script_path.stem}"
    _, exec_module_isolated_from_scripts_dir = _companion_api(script_path.parent)
    spec = importlib.util.spec_from_file_location(name, script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {script_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    exec_module_isolated_from_scripts_dir(spec, module, script_path)
    return module


def ensure_formatter_sibling_modules(script_dir: Path) -> None:
    """Load co-located formatter modules with scripts-dir isolation."""
    parent = script_dir.resolve()
    _load_script_dir_isolated_util(parent)
    _companion_api(parent)
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
    util = _load_script_dir_isolated_util(parent)
    _companion_api(parent)
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
