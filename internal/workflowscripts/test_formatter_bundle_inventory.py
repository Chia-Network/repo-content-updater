"""Regression: single authoritative formatter / DCR script inventory."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from formatter_bundle_inventory import (
    DCR_COMBINE_TEST_BUNDLE,
    FORMATTER_COLD_START_TEST_BUNDLE,
    FORMATTER_RUNTIME_FILENAMES,
    FORMATTER_SIBLING_MODULE_STEMS,
    LOADER_RESOLVE_MARKER_FILENAMES,
    TRUSTED_DCR_SCRIPT_REPO_PATHS,
)
import trusted_formatter_loader as trusted_loader
import trusted_formatter_loader_cold_start as cold_start

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CONFIG = _REPO_ROOT / "config.yaml"
_MANAGED_FILE_PATH = re.compile(
    r"- name: ([^\n]+)\n(?:.*\n)*?    repo_path: ([^\n]+)",
    re.MULTILINE,
)
_DCR_COMPANION_BLOCK = re.compile(
    r"- name: dependency-cursor-review\n(?:.*\n)*?    companion_files:\n((?:      - .+\n)+)",
    re.MULTILINE,
)


class FormatterBundleInventoryTest(unittest.TestCase):
    def test_loader_stems_match_inventory(self) -> None:
        self.assertEqual(
            FORMATTER_SIBLING_MODULE_STEMS,
            trusted_loader.FORMATTER_SIBLING_MODULE_STEMS,
        )

    def test_cold_start_markers_match_inventory(self) -> None:
        self.assertEqual(
            LOADER_RESOLVE_MARKER_FILENAMES,
            cold_start._BUNDLE_MARKERS,
        )

    def test_runtime_bundle_includes_loader_markers_and_siblings(self) -> None:
        for name in LOADER_RESOLVE_MARKER_FILENAMES:
            self.assertIn(name, FORMATTER_RUNTIME_FILENAMES)
        for stem in FORMATTER_SIBLING_MODULE_STEMS:
            self.assertIn(f"{stem}.py", FORMATTER_RUNTIME_FILENAMES)

    def test_combine_bundle_extends_runtime(self) -> None:
        self.assertGreater(len(DCR_COMBINE_TEST_BUNDLE), len(FORMATTER_COLD_START_TEST_BUNDLE))
        for name in FORMATTER_COLD_START_TEST_BUNDLE:
            self.assertIn(name, DCR_COMBINE_TEST_BUNDLE)

    def test_trusted_manifest_paths_match_config_script_companions(self) -> None:
        config = _CONFIG.read_text(encoding="utf-8")
        companion_block = _DCR_COMPANION_BLOCK.search(config)
        self.assertIsNotNone(companion_block)
        companion_names = [
            line.strip().removeprefix("- ").strip()
            for line in companion_block.group(1).splitlines()
            if line.strip()
        ]
        name_to_path = {
            name: path.strip()
            for name, path in _MANAGED_FILE_PATH.findall(config)
        }
        expected = {
            name_to_path[name]
            for name in companion_names
            if name in name_to_path and name_to_path[name].startswith(".github/scripts/")
        }
        self.assertEqual(set(TRUSTED_DCR_SCRIPT_REPO_PATHS), expected)
