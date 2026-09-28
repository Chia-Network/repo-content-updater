"""Load the malware verdict formatter from an explicit file path (no sys.path prepend)."""

from __future__ import annotations

import sys
import types
from collections.abc import Callable
from pathlib import Path

from companion_isolated_exec import exec_module_isolated_from_scripts_dir

TRUSTED_FORMATTER_MODULE_NAME = "trusted_malware_verdict_formatter"

FORMATTER_SIBLING_MODULE_STEMS = (
    "companion_isolated_exec",
    "malware_verdict_patterns",
    "malware_verdict_policy",
    "malware_verdict_classification",
    "malware_verdict_precedence",
)

_FORMATTER_ENV_PRIMED: set[Path] = set()

# Contract: consumers must call load_format_malware_review_verdict(path) (or
# find_and_load_format_malware_review_verdict) so sibling modules and this loader
# are bootstrapped before the formatter module executes. Do not rely on importing
# malware_verdict_formatter directly from an empty sys.modules.


def import_module_from_trusted_script(
    script_path: Path,
    module_name: str | None = None,
) -> types.ModuleType:
    import importlib.util

    script_path = script_path.resolve()
    name = module_name or f"trusted_script_{script_path.stem}"
    spec = importlib.util.spec_from_file_location(name, script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {script_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    exec_module_isolated_from_scripts_dir(spec, module, script_path)
    return module


def ensure_formatter_sibling_modules(script_dir: Path) -> None:
    """Load co-located formatter modules with scripts-dir isolation (canonical bootstrap)."""
    parent = script_dir.resolve()
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
    """Load loader + formatter sibling modules once per trusted scripts directory."""
    parent = script_dir.resolve()
    if parent in _FORMATTER_ENV_PRIMED:
        return
    _ensure_loader_module(parent)
    ensure_formatter_sibling_modules(parent)
    _FORMATTER_ENV_PRIMED.add(parent)


def _ensure_loader_module(script_dir: Path) -> None:
    loader_path = (script_dir / "trusted_formatter_loader.py").resolve()
    if not loader_path.is_file():
        return
    existing = sys.modules.get("trusted_formatter_loader")
    if existing is not None:
        existing_file = getattr(existing, "__file__", None)
        if existing_file and Path(existing_file).resolve() == loader_path:
            return
    import_module_from_trusted_script(loader_path, "trusted_formatter_loader")


def load_format_malware_review_verdict(script_path: Path) -> Callable[[str], str]:
    """Return format_malware_review_verdict loaded from an explicit trusted file path.

    This is the supported entrypoint: it primes trusted_formatter_loader and formatter
    sibling modules (patterns/classification/precedence) before executing the formatter
    module, so callers never depend on undocumented sys.modules priming.
    """
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
