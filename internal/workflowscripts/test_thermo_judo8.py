"""Thermonuclear judo #8/#9 regression guards."""

from __future__ import annotations

import ast
import inspect
import subprocess
import unittest
from pathlib import Path

import trusted_formatter_loader_cold_start as cold_start

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPTS = Path(__file__).resolve().parent

_POLICY_MODULE_BOUNDS: tuple[tuple[str, int], ...] = (
    ("malware_verdict_policy.py", 25),
    ("malware_verdict_policy_view.py", 45),
    ("malware_verdict_policy_selection.py", 320),
    ("malware_verdict_policy_context.py", 100),
    ("scripts_dir_path_scrub.py", 45),
    ("scripts_dir_module_loader.py", 25),
    ("formatter_runtime_bundle.py", 40),
    ("formatter_bundle_inventory.py", 220),
    ("malware_verdict_policy_rules.py", 680),
    ("malware_verdict_policy_analysis.py", 55),
    ("malware_verdict_patterns.py", 530),
    ("isolated_module_exec.py", 110),
    ("trusted_formatter_loader_cold_start.py", 110),
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
        hop_src = inspect.getsource(cold_start._cold_start_hop_load_scripts_dir_module_loader)
        hop_tree = ast.parse(hop_src)
        hop_exec_calls = [
            node
            for node in ast.walk(hop_tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "exec_scripts_dir_module"
        ]
        self.assertNotIn("def _exec_module_isolated", combine)
        self.assertIn("runpy.run_path", combine)
        self.assertIn("resolve_loader_bundle", combine)
        self.assertIn("bootstrap_module_from_scripts_dir", iso_src)
        self.assertIn("register_util_from_scripts_dir", iso_src)
        self.assertIn("resolve_trusted_formatter_loader_for_dir", iso_src)
        self.assertIn("bootstrap_scripts_dir_path_scrub", cold_src)
        self.assertIn("_cold_start_hop_load_scripts_dir_module_loader", cold_src)
        self.assertNotIn("def _module_exec_scrub", cold_src)
        self.assertNotIn("cold_start_hop_load_self", hop_src)
        self.assertTrue(
            hop_exec_calls,
            msg="cold-start loader hop must call scripts_dir_path_scrub.exec_scripts_dir_module",
        )
        self.assertNotIn("def bootstrap_scripts_dir_path_scrub", iso_src)
        self.assertNotIn("def _bootstrap_scripts_dir_path_scrub", iso_src)
        self.assertIn("_require_scripts_dir_path_scrub", iso_src)
        self.assertNotIn("register_util_from_disk", cold_src)
        self.assertIn("register_util_from_scripts_dir", cold_src)
        self.assertFalse(
            (_SCRIPTS / "dependency_cursor_review_trusted_loader.py").exists()
        )
        self.assertFalse((_SCRIPTS / "companion_isolated_exec.py").exists())
        self.assertFalse((_SCRIPTS / "script_dir_isolated_load.py").exists())
        self.assertFalse((_SCRIPTS / "malware_verdict_policy_lexical.py").exists())

    def test_policy_split_semantics_and_module_size_caps(self) -> None:
        deploy = (_SCRIPTS / "malware_verdict_policy.py").read_text(encoding="utf-8")
        analysis = (_SCRIPTS / "malware_verdict_policy_analysis.py").read_text(
            encoding="utf-8"
        )
        view = (_SCRIPTS / "malware_verdict_policy_view.py").read_text(encoding="utf-8")
        selection = (_SCRIPTS / "malware_verdict_policy_selection.py").read_text(
            encoding="utf-8"
        )
        context = (_SCRIPTS / "malware_verdict_policy_context.py").read_text(
            encoding="utf-8"
        )
        rules = (_SCRIPTS / "malware_verdict_policy_rules.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("format_verdict_text", deploy)
        self.assertNotIn(
            "from malware_verdict_policy_analysis import",
            deploy.split("def format_verdict_text")[0],
        )
        self.assertIn("class VerdictAnalysis", analysis)
        self.assertIn("collect_body_strip_spans", rules)
        self.assertNotIn("_BODY_STRIP_SPAN", analysis)
        self.assertIn("class FormatterPolicyView", view)
        self.assertIn("tuple[VerdictMention", view)
        self.assertIn("build_official_selection_context", selection)
        self.assertIn("OfficialSelectionContext", selection)
        self.assertIn("mention_loses_to_official", context)
        self.assertIn("_OFFICIAL_SELECT_PIPELINE", rules)
        self.assertIn("_BODY_STRIP_RULES", rules)
        self.assertNotIn("from malware_verdict_classification import", deploy)
        self.assertFalse((_SCRIPTS / "malware_verdict_policy_rules_select.py").exists())
        self.assertFalse((_SCRIPTS / "malware_verdict_policy_rules_strip.py").exists())
        self.assertFalse(
            (_SCRIPTS / "malware_verdict_policy_catalog.py").exists(),
        )
        self.assertFalse((_SCRIPTS / "module_exec_scrub_bootstrap.py").exists())
        self.assertFalse((_SCRIPTS / "trusted_formatter_loader_bootstrap.py").exists())
        self.assertFalse((_SCRIPTS / "module_exec_scrub.py").exists())
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
            "scripts-dir-path-scrub.py",
            "scripts-dir-module-loader.py",
            "formatter-runtime-bundle.py",
            "malware-verdict-policy-context.py",
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
        manifest_text = manifest.read_text(encoding="utf-8")
        self.assertIn(".github/scripts/malware_verdict_formatter.py", manifest_text)
        self.assertIn(".github/scripts/malware_verdict_policy_rules.py", manifest_text)
        self.assertIn(".github/scripts/malware_verdict_policy_selection.py", manifest_text)
        self.assertNotIn(
            ".github/scripts/malware_verdict_policy_rules_select.py", manifest_text
        )
        self.assertNotIn(".github/scripts/script_dir_isolated_load.py", manifest_text)
        self.assertNotIn(".github/scripts/malware_verdict_policy_lexical.py", manifest_text)


if __name__ == "__main__":
    unittest.main()
