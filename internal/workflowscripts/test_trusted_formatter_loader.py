"""Tests for trusted_formatter_loader (canonical importlib bootstrap)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import sys

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


class TrustedFormatterLoaderTest(unittest.TestCase):
    def test_managed_loader_template_matches_canonical_module(self) -> None:
        self.assertTrue(_LOADER_TEMPLATE.is_file())
        self.assertEqual(
            _LOADER_TEMPLATE.read_text(encoding="utf-8"),
            _CANONICAL_LOADER.read_text(encoding="utf-8"),
        )

    def test_find_and_load_internal_canonical_formatter(self) -> None:
        format_fn = find_and_load_format_malware_review_verdict(_SCRIPTS)
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
            (scripts / "re.py").write_text(
                "raise RuntimeError('untrusted re shadow')\n",
                encoding="utf-8",
            )
            import sys

            script_dir = str(scripts.resolve())
            sys.path.insert(0, script_dir)
            try:
                format_fn = load_format_malware_review_verdict(trusted)
            finally:
                sys.path[:] = [p for p in sys.path if p != script_dir]
            result = format_fn("Verdict: benign\n\nDetails.")
            self.assertTrue(result.startswith("**Verdict: benign**"))

    def test_cold_load_without_preexisting_loader_modules(self) -> None:
        """Public loader entry must bootstrap siblings without ad hoc sys.modules priming."""
        purge = (
            "trusted_formatter_loader",
            "trusted_malware_verdict_formatter",
            "malware_verdict_formatter",
            "malware_verdict_patterns",
            "malware_verdict_precedence",
            "malware_verdict_classification",
        )
        saved = {name: sys.modules.pop(name, None) for name in purge}
        try:
            format_fn = load_format_malware_review_verdict(_CANONICAL)
            result = format_fn("Verdict: benign\n\nDetails.")
            self.assertTrue(result.startswith("**Verdict: benign**"))
        finally:
            for name, module in saved.items():
                if module is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = module

    def test_workflow_yaml_bootstrap_pattern_loads_formatter(self) -> None:
        """Simulate dependency-cursor-review YAML: stdlib exec bootstrap, then load_loader_module."""
        import importlib.util
        import sys

        purge = (
            "trusted_formatter_loader",
            "trusted_formatter_loader_bootstrap",
            "trusted_malware_verdict_formatter",
            "malware_verdict_formatter",
            "malware_verdict_patterns",
            "malware_verdict_precedence",
            "malware_verdict_classification",
        )
        saved = {name: sys.modules.pop(name, None) for name in purge}
        try:
            script_dir = _SCRIPTS
            bootstrap_path = script_dir / "trusted_formatter_loader_bootstrap.py"
            loader_path = script_dir / "trusted_formatter_loader.py"
            spec = importlib.util.spec_from_file_location(
                "trusted_formatter_loader_bootstrap", bootstrap_path
            )
            self.assertIsNotNone(spec and spec.loader)
            bootstrap = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = bootstrap
            spec.loader.exec_module(bootstrap)
            loader = bootstrap.load_loader_module(loader_path)
            format_fn = loader.find_and_load_format_malware_review_verdict(script_dir)
            result = format_fn("Verdict: benign\n\nDetails.")
            self.assertTrue(result.startswith("**Verdict: benign**"))
        finally:
            for name, module in saved.items():
                if module is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = module

    def test_e03b8638_load_loader_module_without_primed_bootstrap(self) -> None:
        """Isolated loader exec must not ModuleNotFoundError on bootstrap import (Bugbot e03b8638)."""
        import importlib.util

        with tempfile.TemporaryDirectory() as tmp:
            scripts = Path(tmp) / "scripts"
            scripts.mkdir()
            for filename in (
                "companion_isolated_exec.py",
                "trusted_formatter_loader.py",
                "trusted_formatter_loader_bootstrap.py",
            ):
                src = (_SCRIPTS / filename).read_text(encoding="utf-8")
                (scripts / filename).write_text(src, encoding="utf-8")
            purge = ("trusted_formatter_loader", "trusted_formatter_loader_bootstrap")
            saved = {name: sys.modules.pop(name, None) for name in purge}
            try:
                spec = importlib.util.spec_from_file_location(
                    "trusted_formatter_loader_bootstrap",
                    scripts / "trusted_formatter_loader_bootstrap.py",
                )
                self.assertIsNotNone(spec and spec.loader)
                bootstrap_mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(bootstrap_mod)
                self.assertNotIn("trusted_formatter_loader_bootstrap", sys.modules)
                loader = bootstrap_mod.load_loader_module(
                    scripts / "trusted_formatter_loader.py"
                )
                self.assertIn("trusted_formatter_loader_bootstrap", sys.modules)
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
            loader_src = _CANONICAL_LOADER.read_text(encoding="utf-8")
            bootstrap_src = (_SCRIPTS / "trusted_formatter_loader_bootstrap.py").read_text(
                encoding="utf-8"
            )
            companion_src = (_SCRIPTS / "companion_isolated_exec.py").read_text(
                encoding="utf-8"
            )
            (scripts / "trusted_formatter_loader.py").write_text(loader_src, encoding="utf-8")
            (scripts / "trusted_formatter_loader_bootstrap.py").write_text(
                bootstrap_src, encoding="utf-8"
            )
            (scripts / "companion_isolated_exec.py").write_text(
                companion_src, encoding="utf-8"
            )
            (scripts / "importlib.py").write_text(
                "raise RuntimeError('untrusted importlib shadow')\n",
                encoding="utf-8",
            )
            script_dir = str(scripts.resolve())
            sys.path.insert(0, script_dir)
            purge = ("trusted_formatter_loader", "trusted_formatter_loader_bootstrap")
            saved = {name: sys.modules.pop(name, None) for name in purge}
            try:
                import importlib.util

                spec = importlib.util.spec_from_file_location(
                    "trusted_formatter_loader_bootstrap",
                    scripts / "trusted_formatter_loader_bootstrap.py",
                )
                bootstrap_mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(bootstrap_mod)
                module = bootstrap_mod.load_loader_module(
                    scripts / "trusted_formatter_loader.py"
                )
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
            format_fn = load_format_malware_review_verdict(trusted)
            result = format_fn("Verdict: benign\n\nDetails.")
            self.assertTrue(result.startswith("**Verdict: benign**"))
            self.assertNotIn("hijacked", result)


if __name__ == "__main__":
    unittest.main()
