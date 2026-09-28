"""Thermonuclear judo #8/#9 regression guards."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPTS = Path(__file__).resolve().parent

_POLICY_MODULE_BOUNDS: tuple[tuple[str, int], ...] = (
    ("malware_verdict_policy.py", 25),
    ("malware_verdict_policy_types.py", 50),
    ("malware_verdict_policy_lexical.py", 35),
    ("malware_verdict_policy_selection_context.py", 320),
    ("malware_verdict_policy_context.py", 130),
    ("module_exec_scrub.py", 60),
    ("formatter_bundle_inventory.py", 95),
    ("malware_verdict_policy_rules_select.py", 360),
    ("malware_verdict_policy_rules_strip.py", 300),
    ("malware_verdict_policy_rules.py", 45),
    ("malware_verdict_policy_analysis.py", 60),
    ("malware_verdict_patterns_regex.py", 185),
    ("malware_verdict_patterns_structure.py", 340),
    ("malware_verdict_patterns.py", 55),
    ("isolated_module_exec.py", 75),
)


class ThermoJudo8Test(unittest.TestCase):
    def test_single_canonical_isolated_exec_module(self) -> None:
        combine = (_SCRIPTS / "dependency_cursor_review_combine_outputs.py").read_text(
            encoding="utf-8"
        )
        cold_src = (
            _SCRIPTS / "trusted_formatter_loader_cold_start.py"
        ).read_text(encoding="utf-8")
        iso_src = (_SCRIPTS / "isolated_module_exec.py").read_text(encoding="utf-8")
        util_src = (_SCRIPTS / "script_dir_isolated_load.py").read_text(encoding="utf-8")
        self.assertNotIn("def _exec_module_isolated", combine)
        self.assertIn("runpy.run_path", combine)
        self.assertIn("resolve_loader_bundle", combine)
        self.assertIn("exec_module_scrubbing_script_dir", iso_src)
        self.assertIn("register_util_from_scripts_dir", iso_src)
        self.assertIn("module_exec_scrub", cold_src)
        self.assertIn("exec_module_scrubbing_script_dir", iso_src)
        self.assertNotIn("def _exec_module_scrubbing_script_dir", cold_src)
        self.assertNotIn("register_util_from_disk", cold_src)
        self.assertIn("register_util_from_scripts_dir", cold_src)
        self.assertNotIn("resolve_trusted_formatter_loader_module", util_src)
        self.assertFalse(
            (_SCRIPTS / "dependency_cursor_review_trusted_loader.py").exists()
        )
        self.assertFalse((_SCRIPTS / "companion_isolated_exec.py").exists())

    def test_policy_split_semantics_and_module_size_caps(self) -> None:
        deploy = (_SCRIPTS / "malware_verdict_policy.py").read_text(encoding="utf-8")
        analysis = (_SCRIPTS / "malware_verdict_policy_analysis.py").read_text(
            encoding="utf-8"
        )
        context = (_SCRIPTS / "malware_verdict_policy_context.py").read_text(
            encoding="utf-8"
        )
        select = (_SCRIPTS / "malware_verdict_policy_rules_select.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("format_verdict_text", deploy)
        self.assertNotIn(
            "from malware_verdict_policy_analysis import",
            deploy.split("def format_verdict_text")[0],
        )
        self.assertIn("class VerdictAnalysis", analysis)
        selection = (_SCRIPTS / "malware_verdict_policy_selection_context.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("OfficialSelectionContext", selection)
        self.assertIn("build_official_selection_context", selection)
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

    def test_formatter_templates_gitignored_apply_time_sync(self) -> None:
        """Canonical workflowscripts only; templates/ mirrors are sync emit (not committed)."""
        gitignore = (_REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        for pattern in (
            "templates/malware-verdict-*.py",
            "templates/trusted-formatter-loader*.py",
            "templates/module-exec-*.py",
            "templates/formatter-bundle-*.py",
        ):
            self.assertIn(pattern, gitignore, msg=f"missing gitignore pattern {pattern!r}")
        for mirror_name in (
            "module-exec-scrub.py",
            "formatter-bundle-inventory.py",
            "malware-verdict-policy-selection-context.py",
        ):
            mirror_path = _REPO_ROOT / "templates" / mirror_name
            self.assertTrue(
                mirror_path.is_file(),
                f"sync must emit templates/{mirror_name} (run make test)",
            )
            proc = subprocess.run(
                ["git", "check-ignore", "-q", str(mirror_path)],
                cwd=_REPO_ROOT,
                check=False,
            )
            self.assertEqual(
                proc.returncode,
                0,
                msg=f"templates/{mirror_name} must be gitignored (apply-time mirror)",
            )
        manifest = _REPO_ROOT / "templates" / "dependency-cursor-review-trusted-scripts.paths"
        self.assertTrue(
            manifest.is_file(),
            "trusted checkout manifest must be generated by sync (make test)",
        )
        self.assertIn(".github/scripts/malware_verdict_formatter.py", manifest.read_text())


if __name__ == "__main__":
    unittest.main()
