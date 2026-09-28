"""Regression: single authoritative formatter / DCR script inventory."""

from __future__ import annotations

import unittest
from pathlib import Path

import formatter_runtime_bundle
import trusted_formatter_loader_cold_start as cold_start
from formatter_bundle_inventory import (
    CONSUMER_SYNC_CANONICAL_TO_TEMPLATE,
    DCR_COMBINE_TEST_BUNDLE,
    DCR_SYNC_EXTRA_FILENAMES,
    FORMATTER_COLD_START_TEST_BUNDLE,
    managed_formatter_sync_pairs,
    parse_dcr_expanded_managed_names,
    parse_dcr_group_templates,
    trusted_dcr_script_repo_paths,
    validate_config_companion_ordering,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CONFIG = _REPO_ROOT / "config.yaml"
_GOLDEN = _REPO_ROOT / "internal" / "config" / "dcr_managed_companion_names.golden"


class FormatterBundleInventoryTest(unittest.TestCase):
    def test_runtime_bundle_matches_cold_start_markers(self) -> None:
        markers = cold_start._loader_resolve_markers(_SCRIPTS := Path(__file__).resolve().parent)
        self.assertEqual(
            formatter_runtime_bundle.LOADER_RESOLVE_MARKER_FILENAMES,
            markers,
        )

    def test_runtime_bundle_includes_loader_markers_and_siblings(self) -> None:
        for name in formatter_runtime_bundle.LOADER_RESOLVE_MARKER_FILENAMES:
            self.assertIn(name, formatter_runtime_bundle.FORMATTER_RUNTIME_FILENAMES)
        for stem in formatter_runtime_bundle.FORMATTER_SIBLING_MODULE_STEMS:
            self.assertIn(f"{stem}.py", formatter_runtime_bundle.FORMATTER_RUNTIME_FILENAMES)

    def test_cold_start_test_bundle_matches_runtime(self) -> None:
        self.assertEqual(FORMATTER_COLD_START_TEST_BUNDLE, formatter_runtime_bundle.FORMATTER_RUNTIME_FILENAMES)

    def test_combine_bundle_extends_runtime(self) -> None:
        self.assertGreater(len(DCR_COMBINE_TEST_BUNDLE), len(FORMATTER_COLD_START_TEST_BUNDLE))
        for name in FORMATTER_COLD_START_TEST_BUNDLE:
            self.assertIn(name, DCR_COMBINE_TEST_BUNDLE)

    def test_sync_canonical_keys_cover_runtime_and_dcr_extras(self) -> None:
        synced = {canonical for canonical, _ in CONSUMER_SYNC_CANONICAL_TO_TEMPLATE}
        expected = set(formatter_runtime_bundle.FORMATTER_RUNTIME_FILENAMES) | set(
            DCR_SYNC_EXTRA_FILENAMES
        )
        self.assertEqual(synced, expected)

    def test_managed_formatter_sync_pairs_match_consumer_face(self) -> None:
        expected = tuple(
            (template, canonical)
            for canonical, template in CONSUMER_SYNC_CANONICAL_TO_TEMPLATE
        )
        self.assertEqual(managed_formatter_sync_pairs(), expected)

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
        self.assertEqual(trusted_dcr_script_repo_paths(config), trusted_dcr_script_repo_paths(config))
        manifest = (_REPO_ROOT / "templates" / "dependency-cursor-review-trusted-scripts.paths").read_text(
            encoding="utf-8"
        )
        expected = set(trusted_dcr_script_repo_paths(config))
        manifest_paths = {line.strip() for line in manifest.splitlines() if line.strip()}
        self.assertEqual(expected, manifest_paths)
