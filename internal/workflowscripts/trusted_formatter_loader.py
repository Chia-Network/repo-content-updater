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

_BUNDLE_PRIMED: set[Path] = set()


def _cold_start_module(install_dir: Path):
    install = install_dir.resolve()
    name = "trusted_formatter_loader_cold_start"
    path = install / f"{name}.py"
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


def _util(script_dir: Path):
    util = sys.modules.get("script_dir_isolated_load")
    path = (script_dir.resolve() / "script_dir_isolated_load.py").resolve()
    if util is not None:
        existing_file = getattr(util, "__file__", None)
        if existing_file and Path(existing_file).resolve() == path:
            return util
    raise RuntimeError(
        "script_dir_isolated_load is not registered; resolve the formatter loader bundle first"
    )


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


def ensure_formatter_bundle(script_dir: Path) -> types.ModuleType:
    """Idempotent: resolve loader + formatter sibling modules (single graph)."""
    parent = script_dir.resolve()
    loader = sys.modules.get("trusted_formatter_loader")
    loader_ok = loader is not None and Path(
        getattr(loader, "__file__", "")
    ).resolve().parent == parent
    if loader_ok and parent in _BUNDLE_PRIMED:
        return loader
    cold_start = _cold_start_module(parent)
    loader = cold_start.resolve_loader_for_dir(parent)
    _BUNDLE_PRIMED.add(parent)
    return loader


def load_format_malware_review_verdict(script_path: Path) -> Callable[[str], str]:
    """Return format_malware_review_verdict loaded from an explicit trusted file path."""
    script_path = script_path.resolve()
    ensure_formatter_bundle(script_path.parent)
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
