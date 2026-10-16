"""A dependency is covered only when its own scan is conclusive."""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import dependency_update_coverage as coverage


def _clean(name: str, repo: str) -> dict:
    return {
        "status": "clean",
        "warn_only": True,
        "scan_conclusive": True,
        "not_scanned_reason": "",
        "verdict_token_in_tree": False,
        "resolution_strategy": "tag_range",
        "resolved_range": "v1...v2",
        "resolved_from": "a" * 40,
        "resolved_to": "b" * 40,
        "from_tag": "v1",
        "to_tag": "v2",
        "changed_files_count": 1,
        "materialized_count": 1,
        "filtered_count": 0,
        "changed_files": ["pkg/index.js"],
        "errors": [],
        "findings": {"unicode": [], "confusable": [], "ioc": [], "heuristic": []},
        "package_name": name,
        "upstream_repo": repo,
        "from_version": "1.0.0",
        "to_version": "1.1.0",
    }


class DependencyUpdateCoverageTest(unittest.TestCase):
    def test_every_conclusive_scan_covers_the_group(self) -> None:
        report = coverage.aggregate(
            [_clean("lodash", "lodash/lodash"), _clean("semver", "npm/node-semver")]
        )
        self.assertIs(report["scan_conclusive"], True)
        self.assertEqual(report["status"], "clean")
        self.assertEqual(report["not_scanned_reason"], "")

    def test_one_unresolvable_entry_is_inconclusive(self) -> None:
        gap = coverage.uncovered(
            {
                "packageName": "k8s.io/api",
                "fromVersion": "0.29.1",
                "toVersion": "0.29.2",
                "upstreamRepo": "",
            },
            "unresolved",
        )
        records = [_clean("cobra", "spf13/cobra"), gap]
        report = coverage.aggregate(records)
        self.assertIs(report["scan_conclusive"], False)
        self.assertEqual(report["not_scanned_reason"], "incomplete_coverage")
        self.assertTrue(any("k8s.io/api" in item for item in report["errors"]))
        summary = coverage.render_summary(report, records)
        self.assertIn("k8s.io/api", summary)
        self.assertIn("not covered (unresolved)", summary)
        self.assertIn("cobra", summary)
        self.assertIn("covered", summary)

    def test_single_conclusive_scan_passes_through(self) -> None:
        one = _clean("lodash", "lodash/lodash")
        self.assertIs(coverage.aggregate([one])["scan_conclusive"], True)

    def test_main_names_an_unresolvable_entry_and_does_not_clone_it(self) -> None:
        updates = [
            {
                "packageName": "lodash",
                "fromVersion": "4.17.20",
                "toVersion": "4.17.21",
                "upstreamRepo": "lodash/lodash",
            },
            {
                "packageName": "k8s.io/api",
                "fromVersion": "0.29.1",
                "toVersion": "0.29.2",
                "upstreamRepo": "",
            },
        ]
        cloned: list[str] = []

        def no_clone(repo: str, _dest: Path) -> bool:
            cloned.append(repo)
            return False

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "dependency_updates.json").write_text(json.dumps(updates), encoding="utf-8")
            output = root / "github_output.txt"
            previous = os.getcwd()
            previous_output = os.environ.get("GITHUB_OUTPUT")
            os.chdir(root)
            os.environ["GITHUB_OUTPUT"] = str(output)
            try:
                with patch.object(coverage, "_clone", no_clone):
                    coverage.main()
            finally:
                os.chdir(previous)
                if previous_output is None:
                    os.environ.pop("GITHUB_OUTPUT", None)
                else:
                    os.environ["GITHUB_OUTPUT"] = previous_output
            report = json.loads((root / "malware_scan_report.json").read_text(encoding="utf-8"))
            self.assertIs(report["scan_conclusive"], False)
            self.assertEqual(cloned, ["lodash/lodash"])
            summary = (root / "malware_scan_summary.md").read_text(encoding="utf-8")
            self.assertIn("k8s.io/api", summary)
            self.assertIn("not covered", summary)
            self.assertIn("scan_conclusive=false", output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
