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
import malware_verdict_formatter as formatter


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


def _run_listed_scan(base: dict[str, str], head: dict[str, str], updates: list[dict]) -> dict:
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        _git(root, "init", "-b", "main")
        _git(root, "config", "user.email", "coverage-test@example.com")
        _git(root, "config", "user.name", "coverage-test")
        for name, content in base.items():
            _commit(root, name, content, f"base {name}")
        _git(root, "checkout", "-b", "pr")
        for name, content in head.items():
            _commit(root, name, content, f"head {name}")
        (root / "dependency_updates.json").write_text(json.dumps(updates), encoding="utf-8")
        previous = os.getcwd()
        saved = {key: os.environ.get(key) for key in ("PR_BASE_SHA", "GITHUB_BASE_REF", "GITHUB_OUTPUT")}
        os.chdir(root)
        os.environ["PR_BASE_SHA"] = _git(root, "rev-parse", "main")
        os.environ.pop("GITHUB_BASE_REF", None)
        os.environ["GITHUB_OUTPUT"] = str(root / "github_output.txt")

        def fake_scan(update: dict, *_args: object, **_kwargs: object) -> dict:
            return _clean(str(update.get("packageName") or ""), str(update.get("upstreamRepo") or ""))

        try:
            with patch.object(coverage, "_scan_one", fake_scan):
                coverage.main()
        finally:
            os.chdir(previous)
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        return json.loads((root / "malware_scan_report.json").read_text(encoding="utf-8"))


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

    def test_raw_sha_and_branch_are_not_conclusive(self) -> None:
        marker = "RAW_SHA_IOC_9f3a"
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "upstream"
            _git_repo(repo)
            _commit(repo, "pkg/index.js", "module.exports = 1;\n", "clean")
            _git(repo, "tag", "v1.0.0")
            _commit(repo, "pkg/index.js", f"const marker = '{marker}';\n", "payload")
            sha = _git(repo, "rev-parse", "HEAD")
            _git(repo, "branch", "release-branch")
            child = root / "child"
            child.mkdir()
            (child / "dependabot_commits.md").write_text(f"commit {sha}\n", encoding="utf-8")

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
                    "VERSION_RANGE_FROM_BODY",
                )
            }
            os.chdir(root)
            os.environ["MALWARE_IOC_PATTERNS"] = json.dumps([marker])
            os.environ["MALWARE_WARN_ONLY"] = "1"
            os.environ["VERSION_RANGE_FROM_BODY"] = "0"
            for name in saved_env:
                if name not in ("MALWARE_IOC_PATTERNS", "MALWARE_WARN_ONLY", "VERSION_RANGE_FROM_BODY"):
                    os.environ[name] = "[]"

            def scan(to_version: str) -> dict:
                dest = child / to_version.replace("/", "-")
                dest.mkdir()
                return coverage._scan_one(
                    {
                        "packageName": "lodash",
                        "fromVersion": "1.0.0",
                        "toVersion": to_version,
                        "upstreamRepo": "lodash/lodash",
                    },
                    dest,
                    Path(__file__).resolve().parent / "upstream_malware_scan.sh",
                )

            try:
                with patch.object(coverage, "_clone", use_local):
                    by_sha = scan(sha)
                    by_branch = scan("release-branch")
            finally:
                os.chdir(previous)
                for name, value in saved_env.items():
                    if value is None:
                        os.environ.pop(name, None)
                    else:
                        os.environ[name] = value
            self.assertEqual((child / "dependabot_commits.md").read_text(encoding="utf-8"), f"commit {sha}\n")
        for report in (by_sha, by_branch):
            self.assertIs(report["scan_conclusive"], False, msg=report)
            self.assertEqual(report["not_scanned_reason"], "to_ref_unresolved")
            self.assertEqual(report["to_tag"], "")
            self.assertEqual(report["findings"]["ioc"], [])

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
        self.assertEqual(aggregated["status"], "not_scanned")
        self.assertEqual(aggregated["not_scanned_reason"], "incomplete_coverage")
        self.assertIsNone(coverage.agent_target([report]))
        self.assertIsNone(aggregated["agent_target"])

    def test_grouped_incomplete_review_cites_unread_and_is_not_benign(self) -> None:
        covered = _clean("lodash", "lodash/lodash")
        partial = _clean("minimist", "minimistjs/minimist")
        partial["from_tag"] = ""
        partial["to_tag"] = ""
        partial["scan_conclusive"] = False
        partial["status"] = "not_scanned"
        partial["not_scanned_reason"] = "incomplete_coverage"
        partial["unread"] = [{"file": "payload.bin", "cause": "nul blob"}]
        report = coverage.aggregate([covered, partial])
        self.assertIs(report["scan_conclusive"], False)
        self.assertEqual(report["unread"], [{"file": "payload.bin", "cause": "nul blob"}])
        published = formatter.compose_published_review(
            report,
            "MALWARE_REVIEW_VERDICT: benign\n\nNo issues.\n",
            "COMPATIBILITY_RECOMMENDATION: Merge\n\nFine.\n",
        )
        self.assertEqual(published["verdict"], "suspicious")
        self.assertIn("`payload.bin:1`", published["malware_text"])
        self.assertIn("nul blob", published["malware_text"])
        self.assertNotIn("**Verdict: benign**", published["malware_text"])
        self.assertIs(published["may_complete"], False)

        planted = _clean("left-pad", "left-pad/left-pad")
        planted["verdict_token_in_tree"] = True
        planted_report = coverage.aggregate([covered, planted])
        self.assertIs(planted_report["verdict_token_in_tree"], True)
        planted_published = formatter.compose_published_review(
            planted_report,
            "MALWARE_REVIEW_VERDICT: benign\n\nNo issues.\n",
            "COMPATIBILITY_RECOMMENDATION: Merge\n\nFine.\n",
        )
        self.assertNotEqual(planted_published["verdict"], "benign")
        self.assertIs(planted_published["may_complete"], False)

    def test_uncovered_finding_status_is_kept(self) -> None:
        for status in ("fail", "warn"):
            report = _clean("lodash", "lodash/lodash")
            report["from_tag"] = ""
            report["to_tag"] = ""
            report["status"] = status
            report["findings"]["ioc"] = [{"path": "pkg/index.js", "line": 1}]
            aggregated = coverage.aggregate([report])
            self.assertEqual(aggregated["status"], status)
            self.assertIs(aggregated["scan_conclusive"], False)
            self.assertEqual(aggregated["findings"]["ioc"][0]["path"], "pkg/index.js")

    def test_uncovered_fail_returns_after_writing_the_report(self) -> None:
        child = _clean("lodash", "lodash/lodash")
        child["from_tag"] = ""
        child["to_tag"] = ""
        child["status"] = "fail"
        child["findings"]["ioc"] = [{"path": "pkg/index.js", "line": 1, "kind": "ioc", "match": "x"}]
        updates = [
            {
                "packageName": "lodash",
                "fromVersion": "4.17.20",
                "toVersion": "4.17.21",
                "upstreamRepo": "lodash/lodash",
            }
        ]
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "dependency_updates.json").write_text(json.dumps(updates), encoding="utf-8")
            output = root / "github_output.txt"
            previous = os.getcwd()
            saved = os.environ.get("GITHUB_OUTPUT")
            os.chdir(root)
            os.environ["GITHUB_OUTPUT"] = str(output)
            try:
                with patch.object(coverage, "_scan_one", lambda *_args, **_kwargs: child):
                    coverage.main()
            finally:
                os.chdir(previous)
                if saved is None:
                    os.environ.pop("GITHUB_OUTPUT", None)
                else:
                    os.environ["GITHUB_OUTPUT"] = saved
            report = json.loads((root / "malware_scan_report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "fail")
            self.assertIs(report["scan_conclusive"], False)
            self.assertEqual(report["findings"]["ioc"][0]["path"], "pkg/index.js")
            self.assertIn("status=fail", output.read_text(encoding="utf-8"))
            self.assertTrue((root / "malware_scan_summary.md").is_file())

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

    def test_unchanged_version_bytes_and_a_dropped_pin_are_unresolved(self) -> None:
        go_sum = "github.com/spf13/cobra v1.8.1 h1:{hash}\n"
        go_mod = "module example.com/app\n\ngo 1.22\n\nrequire github.com/spf13/cobra v1.8.1\n"
        lock = {
            "lockfileVersion": 3,
            "packages": {
                "node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                    "integrity": "sha512-old",
                }
            },
        }
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _git(root, "init", "-b", "main")
            _git(root, "config", "user.email", "coverage-test@example.com")
            _git(root, "config", "user.name", "coverage-test")
            _commit(root, "go.sum", go_sum.format(hash="a" * 43 + "="), "base go.sum")
            _commit(root, "go.mod", go_mod, "base go.mod")
            _commit(root, "package-lock.json", json.dumps(lock) + "\n", "base lock")
            _commit(root, "requirements.txt", "requests==2.31.0\n", "base requirements")
            _git(root, "checkout", "-b", "pr")
            _commit(root, "go.sum", go_sum.format(hash="b" * 43 + "="), "same version, new hash")
            _commit(
                root,
                "go.mod",
                go_mod + "\nreplace github.com/spf13/cobra => github.com/evil/cobra v1.8.1\n",
                "replace beside the same require",
            )
            lock["packages"]["node_modules/left-pad"]["integrity"] = "sha512-new"
            lock["packages"]["node_modules/left-pad"]["resolved"] = "https://github.com/evil/left-pad/tarball/deadbeef"
            _commit(root, "package-lock.json", json.dumps(lock) + "\n", "integrity and resolved swap")
            _commit(
                root,
                "requirements.txt",
                "requests @ git+https://github.com/evil/requests.git@deadbeef\n",
                "pin replaced by a vcs url",
            )
            (root / "dependency_updates.json").write_text("[]", encoding="utf-8")
            output = root / "github_output.txt"
            previous = os.getcwd()
            saved = {key: os.environ.get(key) for key in ("PR_BASE_SHA", "GITHUB_BASE_REF", "GITHUB_OUTPUT")}
            os.chdir(root)
            os.environ["PR_BASE_SHA"] = _git(root, "rev-parse", "main")
            os.environ.pop("GITHUB_BASE_REF", None)
            os.environ["GITHUB_OUTPUT"] = str(output)
            try:
                coverage.main()
            finally:
                os.chdir(previous)
                for key, value in saved.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value
            report = json.loads((root / "malware_scan_report.json").read_text(encoding="utf-8"))
            names = {item["package_name"] for item in report["dependencies"]}
            self.assertEqual(names, {"go.sum", "go.mod", "package-lock.json", "requests"})
            self.assertTrue(all(item["not_scanned_reason"] == "unresolved" for item in report["dependencies"]))
            self.assertIs(report["scan_conclusive"], False)
            self.assertEqual(report["status"], "not_scanned")
            summary = (root / "malware_scan_summary.md").read_text(encoding="utf-8")
            for name in ("go.sum", "go.mod", "package-lock.json", "requests"):
                self.assertIn(name, summary, msg=summary)
            self.assertNotIn("github.com/spf13/cobra", summary)
            self.assertNotIn("left-pad", summary)

    def test_listed_version_with_other_manifest_bytes_is_unresolved(self) -> None:
        lock = {
            "lockfileVersion": 3,
            "packages": {
                "node_modules/lodash": {
                    "version": "4.17.20",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
                    "integrity": "sha512-lodash-old",
                },
                "node_modules/minimist": {
                    "version": "1.2.8",
                    "resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.8.tgz",
                    "integrity": "sha512-minimist-old",
                },
            },
        }
        go_mod = "module example.com/app\n\ngo 1.22\n\nrequire github.com/spf13/cobra v1.8.0\n"
        foo_mod_hash = "d" * 43 + "="
        go_sum = (
            "github.com/foo/bar v1.0.0 h1:{foo}\n"
            f"github.com/foo/bar v1.0.0/go.mod h1:{foo_mod_hash}\n"
            "github.com/spf13/cobra {ver} h1:{cobra}\n"
            "github.com/spf13/cobra {ver}/go.mod h1:" + ("b" * 43) + "=\n"
        )
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _git(root, "init", "-b", "main")
            _git(root, "config", "user.email", "coverage-test@example.com")
            _git(root, "config", "user.name", "coverage-test")
            _commit(
                root, "package.json", json.dumps({"dependencies": {"lodash": "4.17.20"}}) + "\n", "base package.json"
            )
            _commit(root, "package-lock.json", json.dumps(lock) + "\n", "base lock")
            _commit(root, "go.mod", go_mod, "base go.mod")
            _commit(
                root, "go.sum", go_sum.format(foo="a" * 43 + "=", cobra="c" * 43 + "=", ver="v1.8.0"), "base go.sum"
            )
            _git(root, "checkout", "-b", "pr")
            _commit(
                root, "package.json", json.dumps({"dependencies": {"lodash": "4.17.21"}}) + "\n", "listed lodash bump"
            )
            lock["packages"]["node_modules/lodash"]["version"] = "4.17.21"
            lock["packages"]["node_modules/lodash"]["resolved"] = (
                "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
            )
            lock["packages"]["node_modules/lodash"]["integrity"] = "sha512-lodash-new"
            lock["packages"]["node_modules/minimist"]["resolved"] = "https://github.com/evil/minimist/tarball/deadbeef"
            lock["packages"]["node_modules/minimist"]["integrity"] = "sha512-minimist-new"
            _commit(root, "package-lock.json", json.dumps(lock) + "\n", "lodash bump and minimist swap")
            _commit(
                root,
                "go.mod",
                go_mod.replace("v1.8.0", "v1.8.1")
                + "\nreplace github.com/spf13/cobra => github.com/evil/cobra v1.8.1\n",
                "cobra bump and replace",
            )
            _commit(
                root,
                "go.sum",
                go_sum.format(foo="e" * 43 + "=", cobra="f" * 43 + "=", ver="v1.8.1"),
                "cobra bump and foo hash swap",
            )
            updates = [
                {
                    "packageName": "lodash",
                    "fromVersion": "4.17.20",
                    "toVersion": "4.17.21",
                    "upstreamRepo": "lodash/lodash",
                },
                {
                    "packageName": "github.com/spf13/cobra",
                    "fromVersion": "v1.8.0",
                    "toVersion": "v1.8.1",
                    "upstreamRepo": "spf13/cobra",
                },
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
            names = {item["package_name"] for item in report["dependencies"]}
            for path in ("package-lock.json", "go.mod", "go.sum"):
                self.assertIn(path, names, msg=sorted(names))
            self.assertNotIn("package.json", names)
            self.assertIs(report["scan_conclusive"], False)
            self.assertNotEqual(report["status"], "clean")
            summary = (root / "malware_scan_summary.md").read_text(encoding="utf-8")
            for path in ("package-lock.json", "go.mod", "go.sum"):
                self.assertIn(path, summary, msg=summary)

    def test_listed_lodash_lock_bump_is_conclusive(self) -> None:
        base_lock = {
            "lockfileVersion": 3,
            "packages": {
                "node_modules/lodash": {
                    "version": "4.17.20",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
                    "integrity": "sha512-lodash-old",
                }
            },
        }
        head_lock = {
            "lockfileVersion": 3,
            "packages": {
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-lodash-new",
                }
            },
        }
        report = _run_listed_scan(
            {"package-lock.json": json.dumps(base_lock) + "\n"},
            {"package-lock.json": json.dumps(head_lock) + "\n"},
            [
                {
                    "packageName": "lodash",
                    "fromVersion": "4.17.20",
                    "toVersion": "4.17.21",
                    "upstreamRepo": "lodash/lodash",
                }
            ],
        )
        self.assertIs(report["scan_conclusive"], True)
        self.assertEqual(report["status"], "clean")
        self.assertEqual(report["package_name"], "lodash")

    def test_listed_cobra_sum_bump_is_conclusive(self) -> None:
        def go_sum(version: str, digest: str) -> str:
            return (
                f"github.com/spf13/cobra {version} h1:{digest}\ngithub.com/spf13/cobra {version}/go.mod h1:{digest}\n"
            )

        report = _run_listed_scan(
            {"go.sum": go_sum("v1.8.0", "a" * 43 + "=")},
            {"go.sum": go_sum("v1.8.1", "b" * 43 + "=")},
            [
                {
                    "packageName": "github.com/spf13/cobra",
                    "fromVersion": "v1.8.0",
                    "toVersion": "v1.8.1",
                    "upstreamRepo": "spf13/cobra",
                }
            ],
        )
        self.assertIs(report["scan_conclusive"], True)
        self.assertEqual(report["status"], "clean")
        self.assertEqual(report["package_name"], "github.com/spf13/cobra")

    def test_listed_go_versions_match_without_a_leading_v(self) -> None:
        def go_mod(version: str) -> str:
            return f"module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/spf13/cobra {version}\n)\n"

        def go_sum(version: str, digest: str) -> str:
            return (
                f"github.com/spf13/cobra {version} h1:{digest}\ngithub.com/spf13/cobra {version}/go.mod h1:{digest}\n"
            )

        report = _run_listed_scan(
            {"go.mod": go_mod("v1.8.0"), "go.sum": go_sum("v1.8.0", "a" * 43 + "=")},
            {"go.mod": go_mod("v1.8.1"), "go.sum": go_sum("v1.8.1", "b" * 43 + "=")},
            [
                {
                    "packageName": "github.com/spf13/cobra",
                    "fromVersion": "1.8.0",
                    "toVersion": "1.8.1",
                    "upstreamRepo": "spf13/cobra",
                }
            ],
        )
        self.assertIs(report["scan_conclusive"], True)
        self.assertEqual(report["status"], "clean")
        self.assertEqual(report["package_name"], "github.com/spf13/cobra")

    def test_listed_npm_range_bump_is_conclusive(self) -> None:
        report = _run_listed_scan(
            {"package.json": json.dumps({"dependencies": {"lodash": "^4.17.20"}}) + "\n"},
            {"package.json": json.dumps({"dependencies": {"lodash": "^4.17.21"}}) + "\n"},
            [
                {
                    "packageName": "lodash",
                    "fromVersion": "4.17.20",
                    "toVersion": "4.17.21",
                    "upstreamRepo": "lodash/lodash",
                }
            ],
        )
        self.assertIs(report["scan_conclusive"], True)
        self.assertEqual(report["status"], "clean")

    def test_changed_range_prefix_is_unresolved(self) -> None:
        report = _run_listed_scan(
            {"package.json": json.dumps({"dependencies": {"lodash": "4.17.20"}}) + "\n"},
            {"package.json": json.dumps({"dependencies": {"lodash": "^4.17.21"}}) + "\n"},
            [
                {
                    "packageName": "lodash",
                    "fromVersion": "4.17.20",
                    "toVersion": "4.17.21",
                    "upstreamRepo": "lodash/lodash",
                }
            ],
        )
        names = {item["package_name"] for item in report["dependencies"]}
        self.assertIn("package.json", names)
        self.assertIs(report["scan_conclusive"], False)
        self.assertNotEqual(report["status"], "clean")

    def test_replace_block_keeps_the_module_file_unresolved(self) -> None:
        def go_mod(version: str, target: str) -> str:
            return (
                "module example.com/app\n\ngo 1.22\n\n"
                f"require github.com/spf13/cobra {version}\n\n"
                "replace (\n"
                f"\tgithub.com/spf13/cobra {version} => {target} {version}\n"
                ")\n"
            )

        report = _run_listed_scan(
            {"go.mod": go_mod("v1.8.0", "github.com/spf13/cobra")},
            {"go.mod": go_mod("v1.8.1", "github.com/evil/cobra")},
            [
                {
                    "packageName": "github.com/spf13/cobra",
                    "fromVersion": "1.8.0",
                    "toVersion": "1.8.1",
                    "upstreamRepo": "spf13/cobra",
                }
            ],
        )
        names = {item["package_name"] for item in report["dependencies"]}
        self.assertIn("go.mod", names)
        self.assertIs(report["scan_conclusive"], False)
        self.assertNotEqual(report["status"], "clean")

    def test_extra_yarn_descriptor_and_nested_lock_entry_stay_unresolved(self) -> None:
        def yarn(version: str, integrity: str, other: str) -> str:
            return (
                f'lodash@^{version}:\n  version "{version}"\n  integrity "{integrity}"\n\n'
                f'lodash@^3.10.1:\n  version "3.10.1"\n  integrity "{other}"\n'
            )

        def lock(version: str, integrity: str, nested: str) -> str:
            return (
                json.dumps(
                    {
                        "lockfileVersion": 1,
                        "dependencies": {
                            "lodash": {
                                "version": version,
                                "integrity": integrity,
                                "dependencies": {"minimist": {"version": "1.2.8", "integrity": nested}},
                            }
                        },
                    }
                )
                + "\n"
            )

        listed = [
            {
                "packageName": "lodash",
                "fromVersion": "4.17.20",
                "toVersion": "4.17.21",
                "upstreamRepo": "lodash/lodash",
            }
        ]
        clean = _run_listed_scan(
            {
                "yarn.lock": yarn("4.17.20", "sha-old", "sha-other"),
                "package-lock.json": lock("4.17.20", "sha-old", "sha-mini"),
            },
            {
                "yarn.lock": yarn("4.17.21", "sha-new", "sha-other"),
                "package-lock.json": lock("4.17.21", "sha-new", "sha-mini"),
            },
            listed,
        )
        self.assertIs(clean["scan_conclusive"], True)
        self.assertEqual(clean["status"], "clean")
        tainted = _run_listed_scan(
            {
                "yarn.lock": yarn("4.17.20", "sha-old", "sha-other"),
                "package-lock.json": lock("4.17.20", "sha-old", "sha-mini"),
            },
            {
                "yarn.lock": yarn("4.17.21", "sha-new", "sha-evil"),
                "package-lock.json": lock("4.17.21", "sha-new", "sha-evil"),
            },
            listed,
        )
        names = {item["package_name"] for item in tainted["dependencies"]}
        self.assertIn("yarn.lock", names)
        self.assertIn("package-lock.json", names)
        self.assertIs(tainted["scan_conclusive"], False)
        self.assertNotEqual(tainted["status"], "clean")

    def test_empty_from_still_scans_the_to_tree(self) -> None:
        update = {
            "packageName": "lodash",
            "fromVersion": "",
            "toVersion": "1.1.0",
            "upstreamRepo": "lodash/lodash",
        }
        self.assertTrue(coverage.scannable(update))
        self.assertFalse(coverage.scannable({**update, "toVersion": ""}))
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "scan.sh"
            script.write_text(
                "#!/bin/bash\n"
                'test -n "$TO_VERSION"\n'
                'test -z "${FROM_VERSION:-}"\n'
                "cat > malware_scan_report.json <<'EOF'\n"
                '{"status":"fail","scan_conclusive":true,"from_tag":"","to_tag":"v1.1.0",'
                '"findings":{"ioc":[{"path":"pkg/index.js","line":1,"kind":"ioc","text":"marker"}],'
                '"unicode":[],"confusable":[],"heuristic":[]}}\n'
                "EOF\n",
                encoding="utf-8",
            )
            dest = root / "child"
            dest.mkdir()
            with patch.object(coverage, "_clone", lambda *_args, **_kwargs: True):
                record = coverage._scan_one(update, dest, script)
        self.assertEqual(record["status"], "fail")
        self.assertEqual(record["findings"]["ioc"][0]["path"], "pkg/index.js")
        report = coverage.aggregate([record])
        self.assertEqual(report["status"], "fail")
        self.assertIs(report["scan_conclusive"], False)
        self.assertEqual(report["findings"]["ioc"][0]["path"], "pkg/index.js")


if __name__ == "__main__":
    unittest.main()
