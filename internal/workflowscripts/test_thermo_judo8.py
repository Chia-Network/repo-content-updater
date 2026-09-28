"""Thermonuclear judo #8 regression guards."""

from __future__ import annotations

import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPTS = Path(__file__).resolve().parent


class ThermoJudo8Test(unittest.TestCase):
    def test_single_canonical_isolated_exec_module(self) -> None:
        combine = (_SCRIPTS / "dependency_cursor_review_combine_outputs.py").read_text(
            encoding="utf-8"
        )
        trusted = (_SCRIPTS / "dependency_cursor_review_trusted_loader.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("def _exec_module_isolated", combine)
        self.assertNotIn("def _exec_module_isolated", trusted)
        self.assertIn(
            "exec_module_isolated_from_scripts_dir",
            (_SCRIPTS / "companion_isolated_exec.py").read_text(encoding="utf-8"),
        )

    def test_policy_module_is_implementation_not_facade(self) -> None:
        policy = (_SCRIPTS / "malware_verdict_policy.py").read_text(encoding="utf-8")
        self.assertIn("class VerdictAnalysis", policy)
        self.assertIn("_OFFICIAL_SELECT_PIPELINE", policy)
        self.assertNotIn("from malware_verdict_classification import", policy)
        self.assertNotIn("from malware_verdict_precedence import", policy)
        self.assertGreater(len(policy.splitlines()), 900)

    def test_shim_modules_not_present_in_workflowscripts(self) -> None:
        self.assertFalse((_SCRIPTS / "malware_verdict_classification.py").exists())
        self.assertFalse((_SCRIPTS / "malware_verdict_precedence.py").exists())

    def test_generated_companion_mirrors_gitignored(self) -> None:
        gitignore = (_REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        for pattern in (
            "templates/dependency-cursor-review-*.py",
            "templates/dependency-cursor-review-*.js",
            "templates/upstream-malware-scan*.sh",
            "templates/companion-isolated-exec.py",
        ):
            self.assertIn(pattern, gitignore)


if __name__ == "__main__":
    unittest.main()
