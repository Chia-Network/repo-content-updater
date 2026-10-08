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
    ("malware_verdict_policy_context.py", 330),
    ("malware_verdict_policy_predicates.py", 85),
    ("scripts_dir_disk_exec.py", 65),
    ("scripts_dir_path_scrub.py", 130),
    ("malware_verdict_patterns_regex.py", 200),
    ("malware_verdict_patterns_structure.py", 380),
    ("malware_verdict_policy_rules_select.py", 370),
    ("malware_verdict_policy_rules_strip.py", 360),
    ("formatter_runtime_bundle.py", 40),
    ("formatter_bundle_inventory.py", 220),
    ("malware_verdict_policy_analysis.py", 85),
    ("malware_verdict_patterns.py", 145),
    ("malware_verdict_policy_view.py", 85),
    ("isolated_module_exec.py", 100),
    ("trusted_formatter_loader_cold_start.py", 78),
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
        resolve_src = inspect.getsource(cold_start.resolve_loader_for_dir)
        hop_exec_calls = [
            node
            for node in ast.walk(ast.parse(resolve_src))
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "bootstrap_module_from_scripts_dir"
        ]
        self.assertNotIn("def _exec_module_isolated", combine)
        self.assertIn("runpy.run_path", combine)
        self.assertIn("resolve_loader_bundle", combine)
        self.assertNotIn("def bootstrap_module_from_scripts_dir", iso_src)
        self.assertIn("_bootstrap_via_spine", iso_src)
        self.assertIn("register_util_from_scripts_dir", iso_src)
        self.assertIn("resolve_trusted_formatter_loader_for_dir", iso_src)
        self.assertIn("_require_scrub", cold_src)
        self.assertIn("load_scrub_from_disk_under_dash_i", (_SCRIPTS / "scripts_dir_path_scrub.py").read_text())
        self.assertIn("_bootstrap_disk_exec", cold_src)
        self.assertTrue((_SCRIPTS / "scripts_dir_disk_exec.py").is_file())
        self.assertNotIn("scripts_dir_module_loader", cold_src)
        self.assertNotIn("def _module_exec_scrub", cold_src)
        self.assertTrue(
            hop_exec_calls,
            msg="cold-start resolve must bootstrap via path_scrub.bootstrap_module_from_scripts_dir",
        )
        self.assertFalse((_SCRIPTS / "scripts_dir_module_loader.py").exists())
        self.assertFalse((_SCRIPTS / "malware_verdict_policy_selection.py").exists())
        self.assertFalse((_SCRIPTS / "malware_verdict_policy_rules.py").exists())
        self.assertNotIn("def bootstrap_scripts_dir_path_scrub", iso_src)
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
        context = (_SCRIPTS / "malware_verdict_policy_context.py").read_text(
            encoding="utf-8"
        )
        predicates = (_SCRIPTS / "malware_verdict_policy_predicates.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("format_verdict_text", deploy)
        self.assertNotIn(
            "from malware_verdict_policy_analysis import",
            deploy.split("def format_verdict_text")[0],
        )
        self.assertIn("class VerdictAnalysis", analysis)
        self.assertIn("pipeline_rule_catalog", analysis)
        self.assertIn("collect_body_strip_spans", analysis)
        self.assertNotIn("_BODY_STRIP_SPAN", analysis)
        self.assertIn("class FormatterPolicyView", view)
        self.assertIn("tuple[VerdictMention", view)
        self.assertIn("build_official_selection_context", context)
        self.assertIn("OfficialSelectionContext", context)
        self.assertNotIn("build_official_selection_context", view.split("__all__")[1])
        self.assertIn("_line_start_official_from_row_flags", context)
        self.assertFalse(
            (_SCRIPTS / "malware_verdict_policy_official_selection_rows.py").exists()
        )
        self.assertFalse(
            (_SCRIPTS / "malware_verdict_policy_rules_select_precedence.py").exists()
        )
        self.assertIn("mention_loses_to_official", predicates)
        self.assertNotIn("mention_loses_to_official", context)
        self.assertNotIn("from malware_verdict_classification import", deploy)
        self.assertTrue((_SCRIPTS / "malware_verdict_policy_rules_select.py").is_file())
        self.assertTrue((_SCRIPTS / "malware_verdict_policy_rules_strip.py").is_file())
        self.assertTrue((_SCRIPTS / "malware_verdict_patterns_regex.py").is_file())
        self.assertTrue((_SCRIPTS / "malware_verdict_patterns_structure.py").is_file())
        scrub_src = (_SCRIPTS / "scripts_dir_path_scrub.py").read_text()
        iso_src = (_SCRIPTS / "isolated_module_exec.py").read_text(encoding="utf-8")
        self.assertIn("_exec_with_path_filter", scrub_src)
        disk_src = (_SCRIPTS / "scripts_dir_disk_exec.py").read_text()
        self.assertIn("def cached_trusted_module", disk_src)
        self.assertNotIn("from scripts_dir_disk_exec import", scrub_src.split("def load_scrub")[0])
        self.assertIn("chicken_egg_import_disk_exec", disk_src)
        self.assertIn("_paired_chicken_egg_import_disk_exec", scrub_src)
        self.assertIn("ensure_disk_exec", scrub_src)
        self.assertNotIn("_ensure_disk_exec", iso_src)
        self.assertIn("cached_trusted_module", scrub_src)
        self.assertIn("bootstrap_module_from_scripts_dir", scrub_src)
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
            "templates/github-scripts-init.py",
        ):
            self.assertIn(pattern, gitignore, msg=f"missing gitignore pattern {pattern!r}")
        for mirror_name in (
            "scripts-dir-path-scrub.py",
            "formatter-runtime-bundle.py",
            "malware-verdict-policy-context.py",
            "github-scripts-init.py",
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
        self.assertIn(".github/scripts/__init__.py", manifest_text)
        self.assertIn(".github/scripts/malware_verdict_formatter.py", manifest_text)
        self.assertIn(".github/scripts/malware_verdict_policy_analysis.py", manifest_text)
        self.assertIn(".github/scripts/malware_verdict_policy_predicates.py", manifest_text)
        self.assertIn(".github/scripts/malware_verdict_policy_rules_select.py", manifest_text)
        self.assertIn(".github/scripts/malware_verdict_patterns_regex.py", manifest_text)
        self.assertNotIn(".github/scripts/malware_verdict_policy_rules.py", manifest_text)
        self.assertNotIn(".github/scripts/malware_verdict_policy_selection.py", manifest_text)
        self.assertNotIn(".github/scripts/script_dir_isolated_load.py", manifest_text)
        self.assertNotIn(".github/scripts/malware_verdict_policy_lexical.py", manifest_text)


if __name__ == "__main__":
    unittest.main()
