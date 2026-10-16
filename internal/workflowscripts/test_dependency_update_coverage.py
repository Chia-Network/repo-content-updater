"""A dependency is covered only when its own scan is conclusive."""

from __future__ import annotations

import json
import os
import subprocess
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
        first = _clean("lodash", "lodash/lodash")
        second = _clean("semver", "npm/node-semver")
        second["resolved_to"] = "c" * 40
        report = coverage.aggregate([first, second])
        self.assertIs(report["scan_conclusive"], True)
        self.assertEqual(report["status"], "clean")
        self.assertEqual(report["not_scanned_reason"], "")
        self.assertEqual(report["package_name"], "lodash")
        self.assertEqual(report["upstream_repo"], "lodash/lodash")
        self.assertEqual(report["resolved_to"], "b" * 40)

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

    def test_child_scan_sees_the_commit_list(self) -> None:
        update = {
            "packageName": "lodash",
            "fromVersion": "4.17.20",
            "toVersion": "4.17.21",
            "upstreamRepo": "lodash/lodash",
        }
        seen: dict[str, object] = {}

        def fake_clone(_repo: str, dest: Path) -> bool:
            dest.mkdir(parents=True)
            return True

        def fake_run(
            cmd: list[str],
            cwd: Path | None = None,
            env: dict | None = None,
            check: bool = False,
        ) -> subprocess.CompletedProcess[str]:
            del env, check
            assert cwd is not None
            commits = Path(cwd) / "dependabot_commits.md"
            seen["commits"] = commits.read_text(encoding="utf-8")
            (Path(cwd) / "malware_scan_report.json").write_text(
                json.dumps(_clean("lodash", "lodash/lodash")),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(cmd, 0)

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "dependabot_commits.md").write_text("commit abc1234\n", encoding="utf-8")
            previous = os.getcwd()
            os.chdir(root)
            try:
                with (
                    patch.object(coverage, "_clone", fake_clone),
                    patch.object(coverage.subprocess, "run", fake_run),
                ):
                    coverage._scan_one(update, root / "child", root / "upstream_malware_scan.sh")
            finally:
                os.chdir(previous)
        self.assertEqual(seen["commits"], "commit abc1234\n")

    def test_checkout_keeps_the_conclusive_package(self) -> None:
        skipped = _clean("lodash", "lodash/lodash")
        skipped["scan_conclusive"] = False
        skipped["resolved_to"] = "a" * 40
        chosen = _clean("semver", "npm/node-semver")
        chosen["resolved_to"] = "c" * 40
        records = [skipped, chosen]
        report = coverage.aggregate(records)
        self.assertIs(report["scan_conclusive"], False)
        self.assertEqual(report["package_name"], "semver")
        self.assertEqual(report["upstream_repo"], "npm/node-semver")
        self.assertEqual(report["from_version"], "1.0.0")
        self.assertEqual(report["resolved_to"], "c" * 40)

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "github_output.txt"
            scans: list[tuple[dict, Path]] = []
            for record, name in ((skipped, "0"), (chosen, "1")):
                dest = root / name
                marker = dest / ".upstream-dependency"
                marker.mkdir(parents=True)
                (marker / "who").write_text(str(record["package_name"]), encoding="utf-8")
                scans.append((record, dest))
            previous = os.getcwd()
            previous_output = os.environ.get("GITHUB_OUTPUT")
            os.chdir(root)
            os.environ["GITHUB_OUTPUT"] = str(output)
            try:
                coverage._keep_checkout(records, scans)
                coverage._emit(report, "summary\n")
            finally:
                os.chdir(previous)
                if previous_output is None:
                    os.environ.pop("GITHUB_OUTPUT", None)
                else:
                    os.environ["GITHUB_OUTPUT"] = previous_output
            self.assertEqual((root / ".upstream-dependency" / "who").read_text(encoding="utf-8"), "semver")
            self.assertTrue((root / "0" / ".upstream-dependency").is_dir())
            emitted = output.read_text(encoding="utf-8")
            self.assertIn("package_name=semver", emitted)
            self.assertIn("upstream_repo=npm/node-semver", emitted)
            self.assertIn(f"resolved_to={'c' * 40}", emitted)
            self.assertIn("scan_conclusive=false", emitted)


if __name__ == "__main__":
    unittest.main()
