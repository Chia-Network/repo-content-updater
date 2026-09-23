"""Tests for trusted_formatter_loader (canonical importlib bootstrap)."""

from __future__ import annotations

import unittest
from pathlib import Path

from trusted_formatter_loader import (
    TRUSTED_FORMATTER_MODULE_NAME,
    find_and_load_format_malware_review_verdict,
)

_SCRIPTS = Path(__file__).resolve().parent


class TrustedFormatterLoaderTest(unittest.TestCase):
    def test_find_and_load_internal_canonical_formatter(self) -> None:
        format_fn = find_and_load_format_malware_review_verdict(_SCRIPTS)
        result = format_fn("Verdict: benign\n\nDetails.")
        self.assertTrue(result.startswith("**Verdict: benign**"))

    def test_trusted_module_name_is_fixed(self) -> None:
        self.assertEqual(TRUSTED_FORMATTER_MODULE_NAME, "trusted_malware_verdict_formatter")


if __name__ == "__main__":
    unittest.main()
