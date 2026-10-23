"""Regression: single authoritative formatter / DCR script inventory."""

from __future__ import annotations

import unittest
from pathlib import Path

import formatter_runtime_bundle
import trusted_formatter_loader_cold_start as cold_start
from formatter_bundle_inventory import (
    AUTHORING_ONLY_SYNC_CANONICAL_TO_TEMPLATE,
    consumer_sync_canonical_to_template,
    managed_formatter_sync_pairs,
    parse_dcr_expanded_managed_names,
    parse_dcr_group_templates,
    trusted_dcr_script_repo_paths,
    validate_config_companion_ordering,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CONFIG = _REPO_ROOT / "config.yaml"
_GOLDEN = _REPO_ROOT / "internal" / "config" / "dcr_managed_companion_names.golden"
_SCRIPTS = Path(__file__).resolve().parent


class FormatterBundleInventoryTest(unittest.TestCase):
    def test_runtime_bundle_matches_cold_start_markers(self) -> None:
        self.assertEqual(
            formatter_runtime_bundle.LOADER_RESOLVE_MARKER_FILENAMES,
            cold_start.LOADER_RESOLVE_MARKER_FILENAMES,
        )

    def test_runtime_bundle_includes_loader_markers_and_siblings(self) -> None:
        for name in formatter_runtime_bundle.LOADER_RESOLVE_MARKER_FILENAMES:
            self.assertIn(name, formatter_runtime_bundle.FORMATTER_RUNTIME_FILENAMES)
        for stem in formatter_runtime_bundle.FORMATTER_SIBLING_MODULE_STEMS:
            self.assertIn(f"{stem}.py", formatter_runtime_bundle.FORMATTER_RUNTIME_FILENAMES)

    def test_combine_extra_extends_runtime_for_combine_workflow(self) -> None:
        combine_bundle = (
            *formatter_runtime_bundle.FORMATTER_RUNTIME_FILENAMES,
            *formatter_runtime_bundle.DCR_COMBINE_EXTRA_FILENAMES,
        )
        self.assertIn(
            "dependency_cursor_review_combine_outputs.py",
            combine_bundle,
        )

    def test_config_derived_sync_covers_runtime_bundle(self) -> None:
        config = _CONFIG.read_text(encoding="utf-8")
        validate_config_companion_ordering(config)
        synced = {canonical for canonical, _ in consumer_sync_canonical_to_template(config)}
        self.assertTrue(
            set(formatter_runtime_bundle.FORMATTER_RUNTIME_FILENAMES) <= synced
        )

    def test_managed_formatter_sync_pairs_match_config(self) -> None:
        config = _CONFIG.read_text(encoding="utf-8")
        expected = tuple(
            (template, canonical)
            for canonical, template in consumer_sync_canonical_to_template(config)
        )
        self.assertEqual(managed_formatter_sync_pairs(config), expected)

    def test_config_companion_ordering_and_golden(self) -> None:
        config = _CONFIG.read_text(encoding="utf-8")
        validate_config_companion_ordering(config)
        expanded = parse_dcr_expanded_managed_names(config)
        golden = [
            line.strip()
            for line in _GOLDEN.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertEqual(list(expanded), golden)
        self.assertEqual(parse_dcr_group_templates(config), expanded)

    def test_trusted_manifest_paths_match_config_script_companions(self) -> None:
        config = _CONFIG.read_text(encoding="utf-8")
        expected_paths = trusted_dcr_script_repo_paths(config)
        manifest = (_REPO_ROOT / "templates" / "dependency-cursor-review-trusted-scripts.paths").read_text(
            encoding="utf-8"
        )
        manifest_lines = [line.strip() for line in manifest.splitlines() if line.strip()]
        manifest_paths = set(manifest_lines)
        self.assertEqual(set(expected_paths), manifest_paths)
        self.assertEqual(
            len(expected_paths),
            len(manifest_lines),
            msg="trusted manifest must not list any repo_path more than once",
        )

    def test_sync_covers_every_consumer_script_entry(self) -> None:
        config = _CONFIG.read_text(encoding="utf-8")
        consumer = consumer_sync_canonical_to_template(config)
        expected = (
            ("check_node_runtime.sh", "check-node-runtime.sh"),
            ("github_scripts_init.py", "github-scripts-init.py"),
            ("malware_verdict_formatter.py", "malware-verdict-formatter.py"),
            ("scripts_dir_disk_exec.py", "scripts-dir-disk-exec.py"),
            ("scripts_dir_path_scrub.py", "scripts-dir-path-scrub.py"),
            ("formatter_runtime_bundle.py", "formatter-runtime-bundle.py"),
            ("isolated_module_exec.py", "isolated-module-exec.py"),
            ("trusted_formatter_loader.py", "trusted-formatter-loader.py"),
            ("trusted_formatter_loader_cold_start.py", "trusted-formatter-loader-cold-start.py"),
            ("upstream_malware_scan.sh", "upstream-malware-scan.sh"),
            ("dependency_update_coverage.py", "dependency-cursor-review-update-coverage.py"),
            ("dependency_manifest_diff.py", "dependency-cursor-review-manifest-diff.py"),
            ("dependency_manifest_versions.py", "dependency-cursor-review-manifest-versions.py"),
            ("dependency_manifest_go.py", "dependency-cursor-review-manifest-go.py"),
            ("dependency_manifest_npm.py", "dependency-cursor-review-manifest-npm.py"),
            ("dependency_manifest_python.py", "dependency-cursor-review-manifest-python.py"),
            ("dependency_cursor_review_prompts.py", "dependency-cursor-review-prompts.py"),
            ("dependency_cursor_review_combine_outputs.py", "dependency-cursor-review-combine-outputs.py"),
            ("dependency-cursor-review-dependabot-context.js", "dependency-cursor-review-dependabot-context.js"),
            ("dependency-cursor-review-post-comment.js", "dependency-cursor-review-post-comment.js"),
            ("dependency-cursor-review-target-pr.js", "dependency-cursor-review-target-pr.js"),
            ("upstream_malware_scan_lib.sh", "upstream-malware-scan-lib.sh"),
            ("upstream_malware_scan_findings.sh", "upstream-malware-scan-findings.sh"),
            ("upstream_release_checkout.sh", "upstream-release-checkout.sh"),
        )
        self.assertEqual(consumer, expected)
        self.assertNotIn(
            "dependency-cursor-review-trusted-scripts.paths",
            [template for _canonical, template in consumer],
        )
        self.assertEqual(
            AUTHORING_ONLY_SYNC_CANONICAL_TO_TEMPLATE,
            (("formatter_bundle_inventory.py", "formatter-bundle-inventory.py"),),
        )

    def test_trusted_dcr_script_repo_paths_has_no_duplicates(self) -> None:
        config = _CONFIG.read_text(encoding="utf-8")
        paths = trusted_dcr_script_repo_paths(config)
        self.assertEqual(len(paths), len(set(paths)))
