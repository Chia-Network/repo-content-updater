"""Tests for dcr_lock: per-file diff parsers and update-list reconciliation."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from dcr_lock import LockChange, changed_packages, missing_from_metadata


def _diff(path: str, *lines: str) -> str:
    header = f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1,20 +1,20 @@\n"
    return header + "\n".join(lines) + "\n"


class LockDiffTest(unittest.TestCase):
    def test_package_lock_version_change(self) -> None:
        text = _diff(
            "package-lock.json",
            '     "node_modules/left-pad": {',
            '-      "version": "1.0.0",',
            '+      "version": "1.0.1",',
            '       "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.0.1.tgz"',
        )
        self.assertEqual(changed_packages(text), (LockChange("npm_and_yarn", "left-pad", "1.0.0", "1.0.1"),))

    def test_npm_v1_nested_entry_uses_its_package_name(self) -> None:
        text = _diff(
            "package-lock.json",
            '     "left-pad": {',
            '-      "version": "1.0.0"',
            '+      "version": "1.0.1"',
        )
        self.assertEqual(changed_packages(text), (LockChange("npm_and_yarn", "left-pad", "1.0.0", "1.0.1"),))

    def test_yarn_stanza_version_change(self) -> None:
        text = _diff(
            "yarn.lock",
            " left-pad@^1.0.0:",
            '-  version "1.0.0"',
            '+  version "1.0.1"',
            '   resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.0.1.tgz"',
        )
        self.assertEqual(changed_packages(text), (LockChange("npm_and_yarn", "left-pad", "1.0.0", "1.0.1"),))

    def test_pnpm_scoped_entry_version_change(self) -> None:
        text = _diff(
            "pnpm-lock.yaml",
            "-  /@scope/pkg@1.0.0:",
            "+  /@scope/pkg@1.0.1:",
        )
        self.assertEqual(changed_packages(text), (LockChange("npm_and_yarn", "@scope/pkg", "1.0.0", "1.0.1"),))

    def test_poetry_lock_name_and_version_change(self) -> None:
        text = _diff(
            "poetry.lock",
            " [[package]]",
            ' name = "requests"',
            '-version = "2.0.0"',
            '+version = "2.1.0"',
        )
        self.assertEqual(changed_packages(text), (LockChange("pip", "requests", "2.0.0", "2.1.0"),))

    def test_uv_lock_is_a_pip_change(self) -> None:
        text = _diff(
            "uv.lock",
            " [[package]]",
            ' name = "requests"',
            '-version = "2.0.0"',
            '+version = "2.1.0"',
        )
        self.assertEqual(changed_packages(text), (LockChange("pip", "requests", "2.0.0", "2.1.0"),))

    def test_cargo_lock_is_a_cargo_change(self) -> None:
        text = _diff(
            "Cargo.lock",
            " [[package]]",
            ' name = "serde"',
            '-version = "1.0.0"',
            '+version = "1.0.1"',
        )
        self.assertEqual(changed_packages(text), (LockChange("cargo", "serde", "1.0.0", "1.0.1"),))

    def test_requirements_file_is_a_normalized_pip_change(self) -> None:
        text = _diff("requirements-dev.txt", "-Example_Pkg==1.0.0", "+Example_Pkg==1.0.1")
        self.assertEqual(changed_packages(text), (LockChange("pip", "example-pkg", "1.0.0", "1.0.1"),))

    def test_go_sum_version_change(self) -> None:
        text = _diff(
            "go.sum",
            "-example.com/mod v1.0.0 h1:old",
            "+example.com/mod v1.0.1 h1:new",
        )
        self.assertEqual(changed_packages(text), (LockChange("gomod", "example.com/mod", "v1.0.0", "v1.0.1"),))

    def test_go_mod_require_version_change(self) -> None:
        text = _diff(
            "go.mod",
            " require (",
            "-\texample.com/mod v1.0.0",
            "+\texample.com/mod v1.0.1",
            " )",
        )
        self.assertEqual(changed_packages(text), (LockChange("gomod", "example.com/mod", "v1.0.0", "v1.0.1"),))

    def test_workflow_action_sha_change(self) -> None:
        old_sha = "a" * 40
        new_sha = "b" * 40
        text = _diff(
            ".github/workflows/ci.yml",
            f"-      - uses: actions/checkout@{old_sha}",
            f"+      - uses: actions/checkout@{new_sha}",
        )
        self.assertEqual(changed_packages(text), (LockChange("github_actions", "actions/checkout", old_sha, new_sha),))

    def test_workflow_action_subpath_uses_the_repository_name(self) -> None:
        old_sha = "a" * 40
        new_sha = "b" * 40
        text = _diff(
            ".github/workflows/ci.yml",
            f"-      - uses: owner/repo/subdir@{old_sha}",
            f"+      - uses: owner/repo/subdir@{new_sha}",
        )
        self.assertEqual(changed_packages(text), (LockChange("github_actions", "owner/repo", old_sha, new_sha),))

    def test_context_only_file_has_no_change(self) -> None:
        text = _diff(
            "package-lock.json",
            '     "node_modules/left-pad": {',
            '       "version": "1.0.1"',
        )
        self.assertEqual(changed_packages(text), ())

    def test_unrelated_file_is_ignored(self) -> None:
        text = _diff("src/index.js", '-const version = "1.0.0";', '+const version = "1.0.1";')
        self.assertEqual(changed_packages(text), ())

    def test_same_change_in_two_files_is_reported_once(self) -> None:
        package_lock = _diff(
            "package-lock.json",
            '     "node_modules/left-pad": {',
            '-      "version": "1.0.0",',
            '+      "version": "1.0.1",',
        )
        yarn_lock = _diff("yarn.lock", " left-pad@^1.0.0:", '-  version "1.0.0"', '+  version "1.0.1"')
        self.assertEqual(
            changed_packages(package_lock + yarn_lock),
            (LockChange("npm_and_yarn", "left-pad", "1.0.0", "1.0.1"),),
        )


class ReconciliationTest(unittest.TestCase):
    def _changes(self) -> tuple[LockChange, ...]:
        return (
            LockChange("npm_and_yarn", "left-pad", "1.0.0", "1.0.1"),
            LockChange("npm_and_yarn", "right-pad", "2.0.0", "2.0.1"),
        )

    def test_update_list_match_removes_a_change(self) -> None:
        missing = missing_from_metadata(self._changes(), [("npm_and_yarn", "left-pad", "1.0.1")])
        self.assertEqual(missing, (LockChange("npm_and_yarn", "right-pad", "2.0.0", "2.0.1"),))

    def test_a_different_new_version_is_still_missing(self) -> None:
        missing = missing_from_metadata(self._changes(), [("npm_and_yarn", "left-pad", "9.9.9")])
        self.assertEqual(len(missing), 2)

    def test_pip_names_compare_after_pep503_normalization(self) -> None:
        change = LockChange("pip", "Example_Pkg", "1.0.0", "1.0.1")
        self.assertEqual(missing_from_metadata((change,), [("pip", "example-pkg", "1.0.1")]), ())

    def test_go_module_names_stay_case_sensitive(self) -> None:
        change = LockChange("gomod", "example.com/Mod", "v1.0.0", "v1.0.1")
        missing = missing_from_metadata((change,), [("gomod", "example.com/mod", "v1.0.1")])
        self.assertEqual(missing, (change,))
