"""Tests for trusted_formatter_loader (canonical importlib bootstrap)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from trusted_formatter_loader import (
    TRUSTED_FORMATTER_MODULE_NAME,
    find_and_load_format_malware_review_verdict,
    load_format_malware_review_verdict,
)

_SCRIPTS = Path(__file__).resolve().parent
_CANONICAL = _SCRIPTS / "malware_verdict_formatter.py"


class TrustedFormatterLoaderTest(unittest.TestCase):
    def test_find_and_load_internal_canonical_formatter(self) -> None:
        format_fn = find_and_load_format_malware_review_verdict(_SCRIPTS)
        result = format_fn("Verdict: benign\n\nDetails.")
        self.assertTrue(result.startswith("**Verdict: benign**"))

    def test_trusted_module_name_is_fixed(self) -> None:
        self.assertEqual(TRUSTED_FORMATTER_MODULE_NAME, "trusted_malware_verdict_formatter")

    def test_sep25_41480cc0_malicious_re_on_syspath_does_not_shadow_exec(self) -> None:
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
