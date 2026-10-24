"""Regression: single authoritative formatter / DCR script inventory."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

from formatter_bundle_inventory import (
    parse_dcr_companion_files,
    sync_canonical_to_template,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CONFIG = _REPO_ROOT / "config.yaml"
_GOLDEN = _REPO_ROOT / "internal" / "config" / "dcr_managed_companion_names.golden"


class FormatterBundleInventoryTest(unittest.TestCase):
    def test_golden_is_the_workflow_and_its_companions(self) -> None:
        config = _CONFIG.read_text(encoding="utf-8")
        golden = [line.strip() for line in _GOLDEN.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(golden, ["dependency-cursor-review", *parse_dcr_companion_files(config)])

    def test_sync_covers_every_consumer_script_entry(self) -> None:
        config = _CONFIG.read_text(encoding="utf-8")
        expected = (
            ("check_node_runtime.sh", "check-node-runtime.sh"),
            ("github_scripts_init.py", "github-scripts-init.py"),
            ("malware_verdict_formatter.py", "malware-verdict-formatter.py"),
            ("upstream_malware_scan.sh", "upstream-malware-scan.sh"),
            ("dependency_update_coverage.py", "dependency-cursor-review-update-coverage.py"),
            ("dependency_manifest_diff.py", "dependency-cursor-review-manifest-diff.py"),
            ("dependency_cursor_review_versions.py", "dependency-cursor-review-versions.py"),
            ("dependency_cursor_review_ecosystems.py", "dependency-cursor-review-ecosystems.py"),
            ("dependency_cursor_review_upstream.py", "dependency-cursor-review-upstream.py"),
            ("dependency_cursor_review_binding.py", "dependency-cursor-review-binding.py"),
            ("dependency_cursor_review_certificate.py", "dependency-cursor-review-certificate.py"),
            ("dependency_manifest_go.py", "dependency-cursor-review-manifest-go.py"),
            ("dependency_manifest_npm.py", "dependency-cursor-review-manifest-npm.py"),
            ("dependency_manifest_python.py", "dependency-cursor-review-manifest-python.py"),
            ("dependency_manifest_lines.py", "dependency-cursor-review-manifest-lines.py"),
            ("dependency_pep508.py", "dependency-cursor-review-manifest-pep508.py"),
            ("dependency_cursor_review_prompts.py", "dependency-cursor-review-prompts.py"),
            ("dependency_cursor_review_combine_outputs.py", "dependency-cursor-review-combine-outputs.py"),
            ("dependency-cursor-review-dependabot-context.js", "dependency-cursor-review-dependabot-context.js"),
            ("dependency-cursor-review-post-comment.js", "dependency-cursor-review-post-comment.js"),
            ("dependency-cursor-review-target-pr.js", "dependency-cursor-review-target-pr.js"),
            ("upstream_malware_scan_lib.sh", "upstream-malware-scan-lib.sh"),
            ("upstream_malware_scan_findings.sh", "upstream-malware-scan-findings.sh"),
            ("upstream_release_checkout.sh", "upstream-release-checkout.sh"),
        )
        self.assertEqual(sync_canonical_to_template(config), expected)

    def test_every_local_module_a_shipped_script_imports_is_shipped(self) -> None:
        """A consumer runs the scripts with `python3 -I` from one directory, so each sibling module must ship too."""
        shipped = {
            canonical for canonical, _template in sync_canonical_to_template(_CONFIG.read_text(encoding="utf-8"))
        }
        scripts = _REPO_ROOT / "internal" / "workflowscripts"
        local = {path.stem for path in scripts.glob("*.py")}
        for name in sorted(item for item in shipped if item.endswith(".py")):
            tree = ast.parse((scripts / name).read_text(encoding="utf-8"))
            imported = {
                alias.name.split(".")[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.Import)
                for alias in node.names
            }
            imported |= {
                node.module.split(".")[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module and not node.level
            }
            with self.subTest(script=name):
                self.assertLessEqual({f"{module}.py" for module in imported & local}, shipped)


if __name__ == "__main__":
    unittest.main()
