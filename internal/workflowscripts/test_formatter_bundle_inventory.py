"""Regression: single authoritative formatter / DCR script inventory."""

from __future__ import annotations

import unittest
from pathlib import Path

import formatter_runtime_bundle
import trusted_formatter_loader_cold_start as cold_start
from formatter_bundle_inventory import (
    consumer_sync_canonical_to_template,
    managed_formatter_sync_pairs,
    parse_dcr_expanded_managed_names,
    parse_dcr_group_templates,
    sync_canonical_to_template,
    trusted_dcr_script_repo_paths,
    validate_config_companion_ordering,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CONFIG = _REPO_ROOT / "config.yaml"
_GOLDEN = _REPO_ROOT / "internal" / "config" / "dcr_managed_companion_names.golden"
_SCRIPTS = Path(__file__).resolve().parent


class FormatterBundleInventoryTest(unittest.TestCase):
    def test_runtime_bundle_matches_cold_start_markers(self) -> None:
        markers = cold_start._loader_resolve_markers(_SCRIPTS)
        self.assertEqual(
            formatter_runtime_bundle.LOADER_RESOLVE_MARKER_FILENAMES,
            markers,
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
        manifest_paths = {line.strip() for line in manifest.splitlines() if line.strip()}
        self.assertEqual(set(expected_paths), manifest_paths)
        self.assertEqual(len(sync_canonical_to_template(config)), len(managed_formatter_sync_pairs(config)) + 1)
