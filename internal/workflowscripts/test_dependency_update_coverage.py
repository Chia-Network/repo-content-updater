"""A dependency is covered only when its own scan is conclusive."""

from __future__ import annotations

import json
import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import dependency_cursor_review_prompts as prompts
import dependency_update_coverage as coverage


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=False,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "coverage-test",
            "GIT_AUTHOR_EMAIL": "coverage-test@example.com",
            "GIT_COMMITTER_NAME": "coverage-test",
            "GIT_COMMITTER_EMAIL": "coverage-test@example.com",
        },
    )
    if proc.returncode != 0:
        raise AssertionError(f"git {args} failed\n{proc.stderr}")
    return proc.stdout.strip()


def _git_repo(repo: Path) -> None:
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "coverage-test@example.com")
    _git(repo, "config", "user.name", "coverage-test")


def _commit(repo: Path, rel: str, content: str, message: str) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    _git(repo, "add", rel)
    _git(repo, "commit", "-m", message)


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

    def test_isolated_child_searches_listed_commit_blobs(self) -> None:
        marker = "LISTED_COMMIT_IOC_9f3a"
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "upstream"
            _git_repo(repo)
            _commit(repo, "pkg/index.js", "module.exports = 1;\n", "clean")
            _git(repo, "tag", "v1.0.0")
            _commit(repo, "pkg/index.js", f"const marker = '{marker}';\n", "listed")
            sha = _git(repo, "rev-parse", "HEAD")
            _git(repo, "tag", "v1.1.0")
            _commit(repo, "pkg/index.js", "module.exports = 1;\n", "cleaned on main")
            commits = root / "dependabot_commits.md"
            commits.write_text(f"update {sha}\n", encoding="utf-8")
            child = root / "child"
            child.mkdir()
            (child / "dependabot_commits.md").write_text("commit deadbeef\n", encoding="utf-8")

            def use_local(_repo: str, dest: Path) -> bool:
                dest.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(repo, dest, target_is_directory=True)
                return True

            previous = os.getcwd()
            saved_env = {
                name: os.environ.get(name)
                for name in (
                    "MALWARE_IOC_PATTERNS",
                    "MALWARE_WARN_ONLY",
                    "MALWARE_IOC_ALLOWLIST",
                    "MALWARE_UNICODE_ALLOWLIST",
                    "MALWARE_CONFUSABLE_ALLOWLIST",
                    "MALWARE_HEURISTIC_ALLOWLIST",
                )
            }
            os.chdir(root)
            os.environ["MALWARE_IOC_PATTERNS"] = json.dumps([marker])
            os.environ["MALWARE_WARN_ONLY"] = "1"
            for name in saved_env:
                if name not in ("MALWARE_IOC_PATTERNS", "MALWARE_WARN_ONLY"):
                    os.environ[name] = "[]"
            try:
                with patch.object(coverage, "_clone", use_local):
                    report = coverage._scan_one(
                        {
                            "packageName": "lodash",
                            "fromVersion": "9.9.9",
                            "toVersion": "1.1.0",
                            "upstreamRepo": "lodash/lodash",
                        },
                        child,
                        Path(__file__).resolve().parent / "upstream_malware_scan.sh",
                        commits.resolve(),
                    )
            finally:
                os.chdir(previous)
                for name, value in saved_env.items():
                    if value is None:
                        os.environ.pop(name, None)
                    else:
                        os.environ[name] = value
            self.assertEqual((child / "dependabot_commits.md").read_text(encoding="utf-8"), "commit deadbeef\n")
        self.assertEqual(report["resolution_strategy"], "commit_list", msg=report)
        self.assertGreater(len(report["findings"]["ioc"]), 0)
        self.assertIn(marker, json.dumps(report["findings"]["ioc"]))

    def test_checkout_keeps_the_conclusive_package(self) -> None:
        skipped = _clean("lodash", "lodash/lodash")
        skipped["scan_conclusive"] = False
        skipped["from_version"] = "4.17.20"
        skipped["to_version"] = "4.17.21"
        skipped["resolved_to"] = "a" * 40
        chosen = _clean("semver", "npm/node-semver")
        chosen["from_version"] = "7.5.4"
        chosen["to_version"] = "7.6.0"
        chosen["resolved_from"] = "d" * 40
        chosen["resolved_to"] = "c" * 40
        records = [skipped, chosen]
        report = coverage.aggregate(records)
        self.assertEqual(
            coverage.agent_target(records),
            ("semver", "npm/node-semver", "c" * 40),
        )
        self.assertEqual(report["agent_target"], ["semver", "npm/node-semver", "c" * 40])
        self.assertIs(report["scan_conclusive"], False)
        self.assertEqual(report["package_name"], "semver")
        self.assertEqual(report["upstream_repo"], "npm/node-semver")
        self.assertEqual(report["from_version"], "7.5.4")
        self.assertEqual(report["resolved_to"], "c" * 40)
        self.assertEqual(
            coverage.agent_fields(report["agent_candidates"])["package"],
            "semver",
        )

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
            (root / "malware_scan_report.json").write_text(json.dumps(report), encoding="utf-8")
            (root / "dependabot_comment_context.json").write_text(
                json.dumps({"packageName": "lodash", "upstreamRepo": "lodash/lodash"}),
                encoding="utf-8",
            )
            previous = os.getcwd()
            saved = {
                key: os.environ.get(key)
                for key in (
                    "GITHUB_OUTPUT",
                    "PACKAGE_NAME",
                    "FROM_VERSION",
                    "TO_VERSION",
                    "RESOLVED_FROM",
                    "RESOLVED_TO",
                )
            }
            os.chdir(root)
            os.environ["GITHUB_OUTPUT"] = str(output)
            os.environ["PACKAGE_NAME"] = "lodash"
            os.environ["FROM_VERSION"] = "4.17.20"
            os.environ["TO_VERSION"] = "4.17.21"
            os.environ["RESOLVED_FROM"] = "a" * 40
            os.environ["RESOLVED_TO"] = "a" * 40
            try:
                coverage._keep_checkout(records, scans)
                coverage._emit(report, "summary\n")
                fields = prompts._prompt_fields()
            finally:
                os.chdir(previous)
                for key, value in saved.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value
            self.assertEqual(fields["package"], "semver")
            self.assertEqual(fields["from_version"], "7.5.4")
            self.assertEqual(fields["resolved_to"], "c" * 40)
            self.assertEqual((root / ".upstream-dependency" / "who").read_text(encoding="utf-8"), "semver")
            self.assertTrue((root / "0" / ".upstream-dependency").is_dir())
            emitted = output.read_text(encoding="utf-8")
            self.assertIn("package_name=semver", emitted)
            self.assertIn("upstream_repo=npm/node-semver", emitted)
            self.assertIn(f"resolved_to={'c' * 40}", emitted)
            self.assertIn("scan_conclusive=false", emitted)

    def test_conclusive_without_tags_is_not_covered(self) -> None:
        report = _clean("lodash", "lodash/lodash")
        report["from_tag"] = ""
        report["to_tag"] = ""
        report["resolved_from"] = "a" * 40
        report["resolved_to"] = "a" * 40
        report["materialized_count"] = 0
        aggregated = coverage.aggregate([report])
        self.assertIs(aggregated["scan_conclusive"], False)
        self.assertEqual(aggregated["not_scanned_reason"], "incomplete_coverage")
        self.assertIsNone(coverage.agent_target([report]))
        self.assertIsNone(aggregated["agent_target"])

    def test_manifest_bump_missing_from_the_parsed_list_is_unresolved(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _git(root, "init", "-b", "main")
            _git(root, "config", "user.email", "coverage-test@example.com")
            _git(root, "config", "user.name", "coverage-test")
            _commit(root, "package.json", "{}\n", "base")
            _git(root, "checkout", "-b", "pr")
            _commit(
                root,
                "package.json",
                json.dumps({"dependencies": {"lodash": "4.17.21", "left-pad": "1.3.0"}}) + "\n",
                "bump package.json",
            )
            _commit(
                root,
                "package-lock.json",
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {"node_modules/minimist": {"version": "1.2.8"}},
                    }
                )
                + "\n",
                "bump lock",
            )
            _commit(
                root,
                "go.mod",
                "module example.com/app\n\ngo 1.22\n\nrequire github.com/evil/mod v1.2.3\n",
                "bump go.mod",
            )
            _commit(root, "requirements.txt", "requests==2.32.3\n", "bump requirements")
            updates = [
                {
                    "packageName": "lodash",
                    "fromVersion": "4.17.20",
                    "toVersion": "4.17.21",
                    "upstreamRepo": "lodash/lodash",
                }
            ]
            (root / "dependency_updates.json").write_text(json.dumps(updates), encoding="utf-8")
            output = root / "github_output.txt"
            previous = os.getcwd()
            saved = {key: os.environ.get(key) for key in ("PR_BASE_SHA", "GITHUB_BASE_REF", "GITHUB_OUTPUT")}
            os.chdir(root)
            os.environ["PR_BASE_SHA"] = _git(root, "rev-parse", "main")
            os.environ.pop("GITHUB_BASE_REF", None)
            os.environ["GITHUB_OUTPUT"] = str(output)
            try:
                with patch.object(coverage, "_clone", lambda *_args, **_kwargs: False):
                    coverage.main()
            finally:
                os.chdir(previous)
                for key, value in saved.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value
            report = json.loads((root / "malware_scan_report.json").read_text(encoding="utf-8"))
            self.assertIs(report["scan_conclusive"], False)
            summary = (root / "malware_scan_summary.md").read_text(encoding="utf-8")
            for name in ("left-pad", "minimist", "github.com/evil/mod", "requests"):
                self.assertIn(name, summary, msg=summary)
            self.assertIn("scan_conclusive=false", output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
