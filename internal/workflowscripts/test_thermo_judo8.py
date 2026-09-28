"""Thermonuclear judo #8/#9 regression guards."""

from __future__ import annotations

import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPTS = Path(__file__).resolve().parent

_POLICY_MODULE_BOUNDS: tuple[tuple[str, int], ...] = (
    ("malware_verdict_policy.py", 120),
    ("malware_verdict_policy_types.py", 120),
    ("malware_verdict_policy_select.py", 420),
    ("malware_verdict_policy_strip.py", 420),
    ("malware_verdict_policy_analysis.py", 420),
    ("malware_verdict_patterns.py", 520),
)


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
        self.assertIn(
            "load_module_isolated",
            (_SCRIPTS / "script_dir_isolated_load.py").read_text(encoding="utf-8"),
        )

    def test_policy_split_semantics_and_module_size_caps(self) -> None:
        deploy = (_SCRIPTS / "malware_verdict_policy.py").read_text(encoding="utf-8")
        analysis = (_SCRIPTS / "malware_verdict_policy_analysis.py").read_text(
            encoding="utf-8"
        )
        select = (_SCRIPTS / "malware_verdict_policy_select.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("format_verdict_text", deploy)
        self.assertIn("class VerdictAnalysis", analysis)
        self.assertIn("_OFFICIAL_SELECT_PIPELINE", select)
        self.assertNotIn("from malware_verdict_classification import", deploy)
        for filename, max_lines in _POLICY_MODULE_BOUNDS:
            path = _SCRIPTS / filename
            self.assertTrue(path.is_file(), filename)
            line_count = len(path.read_text(encoding="utf-8").splitlines())
            self.assertLessEqual(
                line_count,
                max_lines,
                msg=f"{filename} has {line_count} lines (cap {max_lines})",
            )

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
            "templates/script-dir-isolated-load.py",
        ):
            self.assertIn(pattern, gitignore)


if __name__ == "__main__":
    unittest.main()
