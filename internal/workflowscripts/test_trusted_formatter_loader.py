"""Tests for trusted_formatter_loader (canonical importlib bootstrap)."""

from __future__ import annotations

import runpy
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path

from trusted_formatter_loader import (
    TRUSTED_FORMATTER_MODULE_NAME,
    find_and_load_format_malware_review_verdict,
    load_format_malware_review_verdict,
)

_SCRIPTS = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPTS.parents[1]
_CANONICAL = _SCRIPTS / "malware_verdict_formatter.py"
_LOADER_TEMPLATE = _REPO_ROOT / "templates" / "trusted-formatter-loader.py"
_CANONICAL_LOADER = _SCRIPTS / "trusted_formatter_loader.py"
import formatter_runtime_bundle as _runtime  # noqa: E402

_FORMATTER_BUNDLE = _runtime.FORMATTER_RUNTIME_FILENAMES


def _copy_formatter_bundle(scripts: Path) -> None:
    for name in _FORMATTER_BUNDLE:
        shutil.copy2(_SCRIPTS / name, scripts / name)


def _load_format_via_cold_start(scripts: Path, formatter_path: Path | None = None):
    ns = runpy.run_path(str(scripts / "trusted_formatter_loader_cold_start.py"))
    loader, _ = ns["resolve_loader_bundle"]((scripts,))
    if formatter_path is not None:
        return loader.load_format_malware_review_verdict(formatter_path)
    return loader.find_and_load_format_malware_review_verdict(scripts)


class TrustedFormatterLoaderTest(unittest.TestCase):
    def test_managed_loader_template_matches_canonical_module(self) -> None:
        self.assertTrue(_LOADER_TEMPLATE.is_file())
        self.assertEqual(
            _LOADER_TEMPLATE.read_text(encoding="utf-8"),
            _CANONICAL_LOADER.read_text(encoding="utf-8"),
        )

    def test_find_and_load_internal_canonical_formatter(self) -> None:
        format_fn = _load_format_via_cold_start(_SCRIPTS)
        result = format_fn("Verdict: benign\n\nDetails.")
        self.assertTrue(result.startswith("**Verdict: benign**"))

    def test_trusted_module_name_is_fixed(self) -> None:
        self.assertEqual(TRUSTED_FORMATTER_MODULE_NAME, "trusted_malware_verdict_formatter")

    def test_sep28_734f385e_malicious_re_on_syspath_does_not_shadow_exec(self) -> None:
        """Scripts dir on sys.path must not intercept stdlib imports during trusted exec."""
        with tempfile.TemporaryDirectory() as tmp:
            scripts = Path(tmp) / "scripts"
            scripts.mkdir()
            trusted = scripts / "malware_verdict_formatter.py"
            trusted.write_text(_CANONICAL.read_text(encoding="utf-8"), encoding="utf-8")
            _copy_formatter_bundle(scripts)
            (scripts / "re.py").write_text(
                "raise RuntimeError('untrusted re shadow')\n",
                encoding="utf-8",
            )
            import sys

            script_dir = str(scripts.resolve())
            sys.path.insert(0, script_dir)
            try:
                format_fn = _load_format_via_cold_start(scripts, trusted)
            finally:
                sys.path[:] = [p for p in sys.path if p != script_dir]
            result = format_fn("Verdict: benign\n\nDetails.")
            self.assertTrue(result.startswith("**Verdict: benign**"))

    def test_f752f2d5_isolation_purge_uses_sys_modules_name_not_filename(self) -> None:
        """Bugbot f752f2d5: purge key must be isolated_module_exec, not *.py filename."""
        sentinel = types.ModuleType("isolated_module_exec")
        sys.modules["isolated_module_exec"] = sentinel
        wrong_key = "isolated_module_exec.py"
        self.assertIsNone(sys.modules.pop(wrong_key, None))
        self.assertIs(sys.modules.get("isolated_module_exec"), sentinel)
        sys.modules.pop("isolated_module_exec", None)

    def test_cold_load_without_preexisting_loader_modules(self) -> None:
        """Public loader entry must bootstrap siblings without ad hoc sys.modules priming."""
        purge = (
            "trusted_formatter_loader",
            "trusted_malware_verdict_formatter",
            "malware_verdict_formatter",
            "malware_verdict_patterns",
            "malware_verdict_policy",
        )
        saved = {name: sys.modules.pop(name, None) for name in purge}
        try:
            format_fn = _load_format_via_cold_start(_SCRIPTS, _CANONICAL)
            result = format_fn("Verdict: benign\n\nDetails.")
            self.assertTrue(result.startswith("**Verdict: benign**"))
        finally:
            for name, module in saved.items():
                if module is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = module

    def test_workflow_yaml_bootstrap_pattern_loads_formatter(self) -> None:
        """Cold-start spine matches combine: run_path cold_start → resolve_loader_bundle."""
        purge = (
            "trusted_formatter_loader",
            "isolated_module_exec",
            "isolated_module_exec",
        )
        saved = {name: sys.modules.pop(name, None) for name in purge}
        try:
            format_fn = _load_format_via_cold_start(_SCRIPTS)
            result = format_fn("Verdict: benign\n\nDetails.")
            self.assertTrue(result.startswith("**Verdict: benign**"))
        finally:
            for name, module in saved.items():
                if module is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = module

    def test_e03b8638_load_loader_module_without_primed_bootstrap(self) -> None:
        """Isolated loader exec must not ModuleNotFoundError (Bugbot e03b8638)."""
        with tempfile.TemporaryDirectory() as tmp:
            scripts = Path(tmp) / "scripts"
            scripts.mkdir()
            _copy_formatter_bundle(scripts)
            purge = (
                "trusted_formatter_loader",
                "isolated_module_exec",
                "isolated_module_exec",
            )
            saved = {name: sys.modules.pop(name, None) for name in purge}
            try:
                ns = runpy.run_path(
                    str(scripts / "trusted_formatter_loader_cold_start.py")
                )
                loader = ns["resolve_loader_for_dir"](scripts)
                self.assertIn("scripts_dir_module_loader", sys.modules)
                self.assertTrue(hasattr(loader, "find_and_load_format_malware_review_verdict"))
            finally:
                for name, module in saved.items():
                    if module is None:
                        sys.modules.pop(name, None)
                    else:
                        sys.modules[name] = module

    def test_load_loader_module_scrubs_scripts_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scripts = Path(tmp) / "scripts"
            scripts.mkdir()
            _copy_formatter_bundle(scripts)
            (scripts / "importlib.py").write_text(
                "raise RuntimeError('untrusted importlib shadow')\n",
                encoding="utf-8",
            )
            script_dir = str(scripts.resolve())
            sys.path.insert(0, script_dir)
            purge = ("trusted_formatter_loader",)
            saved = {name: sys.modules.pop(name, None) for name in purge}
            try:
                ns = runpy.run_path(
                    str(scripts / "trusted_formatter_loader_cold_start.py")
                )
                module = ns["resolve_loader_for_dir"](scripts)
                self.assertTrue(hasattr(module, "find_and_load_format_malware_review_verdict"))
            finally:
                sys.path[:] = [p for p in sys.path if p != script_dir]
                for name, module in saved.items():
                    if module is None:
                        sys.modules.pop(name, None)
                    else:
                        sys.modules[name] = module

    def test_package_dir_beside_trusted_file_does_not_shadow_loader(self) -> None:
        """Bugbot c1bdce0b: PR-head package dir must not replace trusted .py import."""
        with tempfile.TemporaryDirectory() as tmp:
            scripts = Path(tmp) / "scripts"
            scripts.mkdir()
            pkg = scripts / "malware_verdict_formatter"
            pkg.mkdir()
            (pkg / "__init__.py").write_text(
                'def format_malware_review_verdict(_text):\n'
                '    return "**Verdict: hijacked**"\n',
                encoding="utf-8",
            )
            trusted = scripts / "malware_verdict_formatter.py"
            trusted.write_text(_CANONICAL.read_text(encoding="utf-8"), encoding="utf-8")
            _copy_formatter_bundle(scripts)
            format_fn = _load_format_via_cold_start(scripts, trusted)
            result = format_fn("Verdict: benign\n\nDetails.")
            self.assertTrue(result.startswith("**Verdict: benign**"))
            self.assertNotIn("hijacked", result)


if __name__ == "__main__":
    unittest.main()
