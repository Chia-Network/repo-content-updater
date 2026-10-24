"""A dependency is covered only when its own scan is conclusive."""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import unittest
from collections.abc import Callable
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import dependency_cursor_review_prompts as prompts
import dependency_cursor_review_upstream as upstream
import dependency_manifest_diff as diff
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


def _clean(name: str, repo: str) -> dict:
    return {
        "status": "clean",
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
        "unread": [],
        "findings": {"unicode": [], "confusable": [], "ioc": [], "heuristic": []},
        "package_name": name,
        "upstream_repo": repo,
        "from_version": "1.0.0",
        "to_version": "1.1.0",
    }


def _found(slug: str) -> upstream.Repo:
    return upstream.Repo(slug, upstream.IDENTITY) if slug else upstream.Repo()


def _plan(*primary: tuple[str, ...], unchecked: tuple = (), gaps: tuple = (), unparsed_locks: tuple = ()) -> diff.Plan:
    """A Plan of (ecosystem, dir, name, old, new) changes."""
    return diff.Plan(
        tuple(diff.Change(*change) for change in primary),
        tuple(diff.Change(*change) for change in unchecked),
        tuple(gaps),
        tuple(unparsed_locks),
    )


def _run_main(
    plan: diff.Plan | None,
    *,
    scan: Callable[..., dict] | None = None,
    repo: Callable[[str, str, str], upstream.Repo] = lambda _ecosystem, name, _version: _found(f"upstream/{name}"),
    clone: Callable[[str, Path], bool] = lambda *_args: False,
    files: Callable[[str], list[str] | None] = lambda _directory: [],
) -> tuple[dict, str, str]:
    """coverage.main() over `plan`: (report, summary, GITHUB_OUTPUT text). `scan` replaces _scan_one, and `files`
    lists a directory at HEAD."""
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        output = root / "github_output.txt"
        with contextlib.ExitStack() as stack:
            stack.enter_context(contextlib.chdir(root))
            stack.enter_context(patch.dict(os.environ, {"GITHUB_OUTPUT": str(output), "DCR_OUT": str(root)}))
            stack.enter_context(patch.object(coverage, "_plan", return_value=plan))
            stack.enter_context(patch.object(coverage._ecosystems, "upstream_repo", repo))
            stack.enter_context(patch.object(coverage, "_clone", clone))
            stack.enter_context(patch.object(coverage, "_git_files", files))
            if scan is not None:
                stack.enter_context(patch.object(coverage, "_scan_one", scan))
            coverage.main()
        report = json.loads((root / "malware_scan_report.json").read_text(encoding="utf-8"))
        return (
            report,
            (root / "malware_scan_summary.md").read_text(encoding="utf-8"),
            output.read_text(encoding="utf-8"),
        )


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
            coverage.Target(package="k8s.io/api", old="0.29.1", new="0.29.2"),
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

    def test_single_update_summary_reflects_coverage_not_the_child_summary(self) -> None:
        child = _clean("lodash", "lodash/lodash")
        child["resolved_from"] = ""
        child["resolved_to"] = ""
        child["scan_conclusive"] = False

        def scan_and_publish(_update: coverage.Target, dest: Path, _script: Path, _ecosystem: str) -> dict:
            (dest / "malware_scan_summary.md").write_text(
                "## Malware Scan Summary\n\n- Status: **clean**\n- Scan coverage: **conclusive**.\n",
                encoding="utf-8",
            )
            return child

        report, summary, _output = _run_main(_plan(("npm", ".", "lodash", "4.17.20", "4.17.21")), scan=scan_and_publish)
        self.assertIs(report["scan_conclusive"], False)
        self.assertIn("Scan coverage: **incomplete**", summary)
        self.assertIn("not covered", summary)
        self.assertNotIn("Scan coverage: **conclusive**", summary)
        self.assertNotIn("Status:", summary)

    def test_main_names_an_unresolvable_entry_and_does_not_clone_it(self) -> None:
        cloned: list[str] = []

        def no_clone(repo: str, _dest: Path) -> bool:
            cloned.append(repo)
            return False

        plan = _plan(("npm", ".", "lodash", "4.17.20", "4.17.21"), ("go", ".", "k8s.io/api", "v0.29.1", "v0.29.2"))
        report, summary, output = _run_main(
            plan,
            repo=lambda _ecosystem, name, _version: _found("lodash/lodash" if name == "lodash" else ""),
            clone=no_clone,
        )
        self.assertIs(report["scan_conclusive"], False)
        self.assertEqual(cloned, ["lodash/lodash"])
        self.assertIn("`k8s.io/api 0.29.1 -> 0.29.2` (no repository): not covered (no_upstream_link)", summary)
        self.assertIn("scan_conclusive=false", output)

    def test_the_report_writes_the_disclosed_lists_the_formatter_reads(self) -> None:
        self.assertEqual(coverage.Disclosure._fields, formatter.DISCLOSED_KEYS)
        report = coverage.aggregate([_clean("lodash", "lodash/lodash")])
        self.assertEqual(
            {key: report[key] for key in formatter.DISCLOSED_KEYS}, {key: [] for key in formatter.DISCLOSED_KEYS}
        )

    def test_each_repository_is_looked_up_once(self) -> None:
        looked_up: list[tuple[str, str, str]] = []

        def repo(ecosystem: str, name: str, version: str) -> upstream.Repo:
            looked_up.append((ecosystem, name, version))
            return _found(f"upstream/{name}")

        plan = _plan(("npm", "a", "lodash", "4.17.20", "4.17.21"), ("npm", "b", "lodash", "4.17.20", "4.17.21"))
        seen: list[coverage.Target] = []
        _run_main(
            plan, repo=repo, scan=lambda target, *_args: seen.append(target) or _clean("lodash", target.repo.slug)
        )
        self.assertEqual(looked_up, [("npm", "lodash", "4.17.21")])
        self.assertEqual([target.repo.slug for target in seen], ["upstream/lodash", "upstream/lodash"])

    def test_versions_that_are_not_exact_stop_before_the_repository_lookup(self) -> None:
        looked_up: list[str] = []

        def repo(_ecosystem: str, name: str, _version: str) -> upstream.Repo:
            looked_up.append(name)
            return _found(f"upstream/{name}")

        plan = _plan(
            ("npm", ".", "left-pad", "^1.2.3", "^1.3.0"),
            ("pip", ".", "requests", "==2.31.0", ">=2.32"),
            ("npm", ".", "nested", "1.0.0, 1.1.0", "1.2.0"),
            ("go", ".", "github.com/spf13/cobra", "v1.8.0", "v1.8.1"),
        )
        seen: list[coverage.Target] = []
        report, _summary, _output = _run_main(plan, repo=repo, scan=lambda update, *_args: seen.append(update) or {})
        self.assertEqual(looked_up, ["github.com/spf13/cobra"])
        self.assertEqual(
            seen,
            [
                coverage.Target(
                    package="github.com/spf13/cobra",
                    old="1.8.0",
                    new="1.8.1",
                    repo=upstream.Repo("upstream/github.com/spf13/cobra", "identity"),
                )
            ],
        )
        reasons = {item["package_name"]: item["not_scanned_reason"] for item in report["dependencies"]}
        self.assertEqual(reasons["left-pad"], "unresolved")
        self.assertEqual(reasons["requests"], "unresolved")
        self.assertEqual(reasons["nested"], "unresolved")

    def test_pip_pins_lose_their_operator_before_the_scan(self) -> None:
        seen: list[coverage.Target] = []
        _run_main(
            _plan(("pip", ".", "requests", "==2.31.0", "==2.32.0")),
            scan=lambda update, *_args: seen.append(update) or _clean("requests", "psf/requests"),
        )
        self.assertEqual((seen[0].old, seen[0].new), ("2.31.0", "2.32.0"))

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
                    "MALWARE_IOC_ALLOWLIST",
                    "MALWARE_UNICODE_ALLOWLIST",
                    "MALWARE_CONFUSABLE_ALLOWLIST",
                    "MALWARE_HEURISTIC_ALLOWLIST",
                )
            }
            os.chdir(root)
            os.environ["MALWARE_IOC_PATTERNS"] = json.dumps([marker])
            for name in saved_env:
                if name != "MALWARE_IOC_PATTERNS":
                    os.environ[name] = "[]"

            def scan(to_version: str) -> dict:
                dest = child / to_version.replace("/", "-")
                dest.mkdir()
                return coverage._scan_one(
                    coverage.Target(package="lodash", old="1.0.0", new=to_version, repo=upstream.Repo("lodash/lodash")),
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
                    "DCR_OUT",
                    "PACKAGE_NAME",
                    "FROM_VERSION",
                    "TO_VERSION",
                    "RESOLVED_FROM",
                    "RESOLVED_TO",
                )
            }
            os.chdir(root)
            os.environ["GITHUB_OUTPUT"] = str(output)
            os.environ["DCR_OUT"] = str(root)
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

    def test_conclusive_without_resolved_releases_is_not_covered(self) -> None:
        report = _clean("lodash", "lodash/lodash")
        report["resolved_from"] = ""
        report["materialized_count"] = 0
        aggregated = coverage.aggregate([report])
        self.assertIs(aggregated["scan_conclusive"], False)
        self.assertEqual(aggregated["status"], "not_scanned")
        self.assertEqual(aggregated["not_scanned_reason"], "incomplete_coverage")
        self.assertIsNone(coverage.agent_target([report]))
        self.assertIsNone(aggregated["agent_target"])

    def test_a_conclusive_untagged_commit_range_is_covered(self) -> None:
        report = _clean("actions/checkout", "actions/checkout")
        report["from_tag"] = ""
        report["to_tag"] = ""
        aggregated = coverage.aggregate([report])
        self.assertIs(aggregated["scan_conclusive"], True)
        self.assertEqual(coverage.agent_target([report]), ("actions/checkout", "actions/checkout", "b" * 40))

    def test_grouped_incomplete_review_cites_unread_and_is_not_benign(self) -> None:
        covered = _clean("lodash", "lodash/lodash")
        partial = _clean("minimist", "minimistjs/minimist")
        partial["resolved_from"] = ""
        partial["resolved_to"] = ""
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
        self.assertEqual(published["verdict"], "inconclusive")
        self.assertIn("`payload.bin`", published["malware_text"])
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
            report["resolved_from"] = ""
            report["resolved_to"] = ""
            report["status"] = status
            report["findings"]["ioc"] = [{"path": "pkg/index.js", "line": 1}]
            aggregated = coverage.aggregate([report])
            self.assertEqual(aggregated["status"], status)
            self.assertIs(aggregated["scan_conclusive"], False)
            self.assertEqual(aggregated["findings"]["ioc"][0]["path"], "pkg/index.js")

    def test_uncovered_fail_returns_after_writing_the_report(self) -> None:
        child = _clean("lodash", "lodash/lodash")
        child["resolved_from"] = ""
        child["resolved_to"] = ""
        child["status"] = "fail"
        child["findings"]["ioc"] = [{"path": "pkg/index.js", "line": 1, "kind": "ioc", "match": "x"}]
        report, summary, output = _run_main(
            _plan(("npm", ".", "lodash", "4.17.20", "4.17.21")), scan=lambda *_args, **_kwargs: child
        )
        self.assertEqual(report["status"], "fail")
        self.assertIs(report["scan_conclusive"], False)
        self.assertEqual(report["findings"]["ioc"][0]["path"], "pkg/index.js")
        self.assertIn("scan_conclusive=false", output)
        self.assertIn("Scan coverage: **incomplete**", summary)

    def test_empty_from_still_scans_the_to_tree(self) -> None:
        update = coverage.Target(package="lodash", old="", new="1.1.0", repo=upstream.Repo("lodash/lodash"))
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

    def test_verify_commit_peels_tags_and_rejects_trees(self) -> None:
        with TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            _git_repo(repo)
            _commit(repo, "f.txt", "x\n", "init")
            commit = _git(repo, "rev-parse", "HEAD")
            tree = _git(repo, "rev-parse", "HEAD^{tree}")
            _git(repo, "tag", "-a", "v1", "-m", "annotated")
            previous = os.getcwd()
            os.chdir(repo)
            try:
                self.assertEqual(coverage._verify_commit(commit), commit)
                self.assertEqual(coverage._verify_commit("v1"), commit)
                self.assertEqual(coverage._verify_commit(tree), "")
                self.assertEqual(coverage._verify_commit("missing"), "")
            finally:
                os.chdir(previous)

    def test_missing_scan_report_fails_the_check(self) -> None:
        update = coverage.Target(package="left-pad", old="1.2.3", new="1.2.4", repo=upstream.Repo("left-pad/left-pad"))
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "scan.sh"
            script.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
            dest = root / "child"
            dest.mkdir()
            with patch.object(coverage, "_clone", lambda *_args, **_kwargs: True):
                record = coverage._scan_one(update, dest, script)
        self.assertEqual(record["not_scanned_reason"], "not_scanned")
        benign = "MALWARE_REVIEW_VERDICT: benign\n\nNo issues.\n"
        merge = "COMPATIBILITY_RECOMMENDATION: Merge\n\nFine.\n"
        published = formatter.compose_published_review(record, benign, merge)
        self.assertEqual(published["check"], "fail")
        self.assertIs(published["may_complete"], False)
        record["not_scanned_reason"] = "not_conclusive"
        concluded = formatter.compose_published_review(record, benign, merge)
        self.assertEqual(concluded["check"], "fail")
        self.assertIs(concluded["may_complete"], False)

    def test_nonzero_exit_after_report_is_a_scanner_error(self) -> None:
        update = coverage.Target(package="left-pad", old="1.2.3", new="1.2.4", repo=upstream.Repo("left-pad/left-pad"))
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "scan.sh"
            script.write_text(
                "#!/bin/bash\n"
                "cat > malware_scan_report.json <<'EOF'\n"
                '{"status":"clean","scan_conclusive":true,"from_tag":"v1.2.3","to_tag":"v1.2.4",'
                '"resolved_from":"a","resolved_to":"b",'
                '"findings":{"unicode":[],"confusable":[],"ioc":[],"heuristic":[]}}\n'
                "EOF\n"
                "echo 'boom after report' >&2\n"
                "exit 1\n",
                encoding="utf-8",
            )
            dest = root / "child"
            dest.mkdir()
            with patch.object(coverage, "_clone", lambda *_args, **_kwargs: True):
                record = coverage._scan_one(update, dest, script)
        self.assertEqual(record["not_scanned_reason"], "scanner_error")
        self.assertIs(record["scan_conclusive"], False)
        self.assertIn("boom after report", record["errors"])
        published = formatter.compose_published_review(
            record, "MALWARE_REVIEW_VERDICT: benign\n\nNo issues.\n", "COMPATIBILITY_RECOMMENDATION: Merge\n"
        )
        self.assertEqual(published["check"], "fail")
        self.assertIs(published["may_complete"], False)

    def test_scan_one_passes_an_absolute_github_output(self) -> None:
        update = coverage.Target(package="left-pad", old="1.2.3", new="1.2.4", repo=upstream.Repo("left-pad/left-pad"))
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "scan.sh"
            script.write_text(
                "#!/bin/bash\n"
                'printf "%s" "$GITHUB_OUTPUT" > github_output_path.txt\n'
                "cat > malware_scan_report.json <<'EOF'\n"
                '{"status":"clean","scan_conclusive":true,"from_tag":"v1.2.3","to_tag":"v1.2.4",'
                '"resolved_from":"a","resolved_to":"b",'
                '"findings":{"unicode":[],"confusable":[],"ioc":[],"heuristic":[]}}\n'
                "EOF\n",
                encoding="utf-8",
            )
            previous = os.getcwd()
            os.chdir(root)
            try:
                dest = Path("child")
                dest.mkdir()
                with patch.object(coverage, "_clone", lambda *_args, **_kwargs: True):
                    coverage._scan_one(update, dest, script)
                child_output = (dest / "github_output_path.txt").read_text(encoding="utf-8")
            finally:
                os.chdir(previous)
        self.assertTrue(os.path.isabs(child_output), child_output)
        self.assertIn(str(Path(tmp).resolve() / "child"), child_output)

    def test_no_upstream_link_writes_a_report(self) -> None:
        report, summary, _output = _run_main(
            _plan(("npm", ".", "lodash", "4.17.20", "4.17.21")), repo=lambda *_args: upstream.Repo()
        )
        self.assertEqual(report["not_scanned_reason"], "no_upstream_link")
        self.assertIs(report["scan_conclusive"], False)
        self.assertIn("no_upstream_link", summary)
        published = formatter.compose_published_review(
            report, "MALWARE_REVIEW_VERDICT: benign\n\nNo issues.\n", "COMPATIBILITY_RECOMMENDATION: Merge\n"
        )
        self.assertEqual(published["check"], "fail")

    def test_a_pip_change_beside_another_configured_package_index_is_not_looked_up(self) -> None:
        config = "registries:\n  extra:\n    type: 'python-index'\n    url: https://example.com/simple/\n"
        looked_up: list[str] = []

        def repo(_ecosystem: str, name: str, _version: str) -> upstream.Repo:
            looked_up.append(name)
            return _found(f"upstream/{name}")

        plan = _plan(("pip", ".", "attrs", "23.1.0", "23.2.0"), ("npm", ".", "lodash", "4.17.20", "4.17.21"))
        texts = {".github/dependabot.yml": config}
        with patch.object(coverage, "_git_text", lambda _rev, path: texts.get(path, "")):
            report, summary, _output = _run_main(
                plan, repo=repo, scan=lambda target, *_args: _clean(target.package, target.repo.slug)
            )
        self.assertEqual(looked_up, ["lodash"])
        self.assertIs(report["scan_conclusive"], False)
        self.assertIn("configured_index", summary)
        self.assertIn(
            "not covered (configured_index). pip may install this from a package index the review does not read.",
            summary,
        )
        published = formatter.compose_published_review(
            report, "MALWARE_REVIEW_VERDICT: benign\n\nNo issues.\n", "COMPATIBILITY_RECOMMENDATION: Merge\n"
        )
        self.assertNotEqual(published["verdict"], "benign")

    def test_a_pip_change_a_trusted_index_serves_is_trusted_and_the_rest_are_looked_up(self) -> None:
        config = (
            "registries:\n  chia:\n    type: python-index\n    url: https://pypi.chia.net/simple\n"
            "    replaces-base: true\n"
        )
        looked_up: list[str] = []
        asked: list[tuple[str, str, frozenset[str], bool]] = []

        def repo(_ecosystem: str, name: str, _version: str) -> upstream.Repo:
            looked_up.append(name)
            return _found(f"upstream/{name}")

        def trusted(
            name: str, version: str, _locked: tuple[str, ...], configured: frozenset[str], replaces_pypi: bool
        ) -> str:
            asked.append((name, version, configured, replaces_pypi))
            return "pypi.chia.net" if name == "chiapos" else ""

        plan = _plan(
            ("pip", ".", "chiapos", "2.0.3", "2.0.4"),
            ("pip", ".", "attrs", "23.1.0", "23.2.0"),
            ("npm", ".", "lodash", "4.17.20", "4.17.21"),
        )
        texts = {".github/dependabot.yml": config}
        with (
            patch.object(coverage, "_git_text", lambda _rev, path: texts.get(path, "")),
            patch.object(upstream, "trusted_python_index", trusted),
        ):
            report, summary, _output = _run_main(
                plan, repo=repo, scan=lambda target, *_args: _clean(target.package, target.repo.slug)
            )
        self.assertEqual(sorted(looked_up), ["attrs", "lodash"])
        self.assertEqual(
            sorted(asked),
            [
                (
                    name,
                    "2.0.4" if name == "chiapos" else "23.2.0",
                    frozenset({"https://pypi.chia.net/simple/"}),
                    True,
                )
                for name in ("attrs", "chiapos")
            ],
        )
        self.assertEqual(
            [(item["name"], item["index"]) for item in report["trusted_packages"]], [("chiapos", "pypi.chia.net")]
        )
        self.assertNotIn("configured_index", summary)
        self.assertIn("configured package indexes are trusted", summary)
        self.assertIn("`chiapos 2.0.3 -> 2.0.4`", summary)
        published = formatter.compose_published_review(
            report, "MALWARE_REVIEW_VERDICT: benign\n\nNo issues.\n", "COMPATIBILITY_RECOMMENDATION: Merge\n"
        )
        without = formatter.compose_published_review(
            {**report, "trusted_packages": []},
            "MALWARE_REVIEW_VERDICT: benign\n\nNo issues.\n",
            "COMPATIBILITY_RECOMMENDATION: Merge\n",
        )
        self.assertEqual((published["verdict"], published["check"]), (without["verdict"], without["check"]))

    def test_a_requirements_index_option_decides_its_directory(self) -> None:
        chia = "https://pypi.chia.net/simple/"
        tree = {
            "plain": ["plain/requirements.txt"],
            "other": ["other/requirements.txt", "other/README.md"],
            "chia": ["chia/requirements.txt"],
            "chained": ["chained/requirements.txt"],
            "outside": ["outside/requirements.txt"],
            "sibling": ["sibling/requirements.txt"],
            "unlisted": None,
        }
        texts = {
            "plain/requirements.txt": "attrs==23.2.0\n",
            "other/requirements.txt": "--extra-index-url=https://example.com/simple\nattrs==23.2.0\n",
            "chia/requirements.txt": f"-i {chia.rstrip('/')}\nattrs==23.2.0\n",
            "chained/requirements.txt": "-r base/requirements-base.txt\n",
            "chained/base/requirements-base.txt": "-ihttps://example.com/simple/\n",
            "outside/requirements.txt": "-r ../../shared/requirements.txt\n",
            "sibling/requirements.txt": "-c ../other/requirements.txt\n",
        }
        expected = {
            "plain": coverage.Indexes(),
            "other": coverage.Indexes(other=True),
            "chia": coverage.Indexes(frozenset({chia}), replaces_pypi=True),
            "chained": coverage.Indexes(other=True),
            "outside": coverage.Indexes(other=True),
            "sibling": coverage.Indexes(other=True),
            "unlisted": coverage.Indexes(other=True),
        }
        with (
            patch.object(coverage, "_git_files", tree.get),
            patch.object(coverage, "_git_text", lambda _rev, path: texts.get(path, "")),
        ):
            for directory, indexes in expected.items():
                with self.subTest(directory):
                    self.assertEqual(coverage._requirements_indexes(directory, coverage.Indexes()), indexes)
            download = coverage.Indexes(frozenset({"https://download.chia.net/simple/"}))
            self.assertEqual(
                coverage._requirements_indexes("chia", download),
                coverage.Indexes(frozenset({chia, "https://download.chia.net/simple/"}), replaces_pypi=True),
            )
            self.assertEqual(coverage._requirements_indexes("plain", coverage.Indexes(other=True)).other, True)

    def test_a_requirements_extra_index_means_the_index_does_not_replace_pypi(self) -> None:
        chia = "https://pypi.chia.net/simple/"
        cases = {
            "index": (f"-i {chia}\nattrs==23.2.0\n", coverage.Indexes(frozenset({chia}), replaces_pypi=True)),
            "extra": (f"--extra-index-url {chia}\nattrs==23.2.0\n", coverage.Indexes(frozenset({chia}))),
            "both": (f"-i {chia}\n--extra-index-url {chia}\nattrs==23.2.0\n", coverage.Indexes(frozenset({chia}))),
        }
        for label, (text, expected) in cases.items():
            with (
                self.subTest(label),
                patch.object(coverage, "_git_files", lambda directory: [f"{directory}/requirements.txt"]),
                patch.object(coverage, "_git_text", lambda _rev, path, text=text: text),
            ):
                self.assertEqual(coverage._requirements_indexes("app", coverage.Indexes()), expected)

    def test_a_dependabot_index_replaces_pypi_only_when_it_says_so(self) -> None:
        chia = "https://pypi.chia.net/simple/"

        def config(replaces: str) -> str:
            return (
                "registries:\n  chia:\n    type: python-index\n"
                f"    url: {chia}\n    replaces-base: {replaces}\n"
            )

        self.assertEqual(
            coverage._python_indexes(config("true")), coverage.Indexes(frozenset({chia}), replaces_pypi=True)
        )
        self.assertEqual(coverage._python_indexes(config("false")), coverage.Indexes(frozenset({chia})))

    def test_git_files_lists_one_directory_at_head(self) -> None:
        with TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            _git_repo(repo)
            _commit(repo, "requirements.txt", "attrs==1.0\n", "root")
            _commit(repo, "app/requirements.txt", "six==1.0\n", "app")
            _commit(repo, "app/deep/requirements.txt", "six==1.0\n", "deep")
            with contextlib.chdir(repo):
                self.assertEqual(coverage._git_files("."), ["app", "requirements.txt"])
                self.assertEqual(coverage._git_files("app"), ["app/deep", "app/requirements.txt"])
            with contextlib.chdir(tmp):
                self.assertIsNone(coverage._git_files("."))

    def test_a_requirements_index_makes_only_its_directory_inconclusive(self) -> None:
        looked_up: list[str] = []

        def repo(_ecosystem: str, name: str, _version: str) -> upstream.Repo:
            looked_up.append(name)
            return _found(f"upstream/{name}")

        plan = _plan(("pip", "app", "attrs", "23.1.0", "23.2.0"), ("pip", "tools", "six", "1.15.0", "1.16.0"))
        texts = {"app/requirements.txt": "--index-url https://example.com/simple/\nattrs==23.2.0\n"}
        with patch.object(coverage, "_git_text", lambda _rev, path: texts.get(path, "")):
            report, summary, _output = _run_main(
                plan,
                repo=repo,
                scan=lambda target, *_args: _clean(target.package, target.repo.slug),
                files=lambda directory: [f"{directory}/requirements.txt"],
            )
        self.assertEqual(looked_up, ["six"])
        self.assertIs(report["scan_conclusive"], False)
        self.assertIn("`attrs 23.1.0 -> 23.2.0` (no repository): not covered (configured_index)", summary)

    def test_only_listed_indexes_are_trusted_and_anything_else_trusts_none(self) -> None:
        chia = "https://pypi.chia.net/simple/"
        download = "https://download.chia.net/simple/"

        def config(*entries: tuple[str, str]) -> str:
            blocks = "".join(
                f"  r{i}:\n    type: {kind}\n    url: {url}  # note\n" for i, (kind, url) in enumerate(entries)
            )
            return f"version: 2\nregistries:\n{blocks}updates:\n  - package-ecosystem: pip\n    registries: '*'\n"

        cases = {
            "both": (config(("python-index", chia), ("python-index", download.rstrip("/"))), {chia, download}, False),
            "none": ("version: 2\n", set(), False),
            "other kind": (config(("npm-registry", "https://npm.example.com")), set(), False),
            "lookalike": (config(("python-index", "https://pypi.chia.net.evil/simple/")), set(), True),
            "plain http": (config(("python-index", "http://pypi.chia.net/simple/")), set(), True),
            "beside unknown": (
                config(("python-index", chia), ("python-index", "https://example.com/simple/")),
                set(),
                True,
            ),
            "unread form": (
                'registries: {x: {type: python-index, url: "https://pypi.chia.net/simple/"}}\n',
                set(),
                True,
            ),
        }
        for label, (text, trusted, other) in cases.items():
            with self.subTest(label):
                self.assertEqual(coverage._python_indexes(text), coverage.Indexes(frozenset(trusted), other))

    def test_unreadable_diff_is_one_unresolved_gap(self) -> None:
        report, summary, _output = _run_main(None)
        self.assertEqual((report["path"], report["not_scanned_reason"]), ("pull request diff", "unresolved"))
        self.assertIn("`pull request diff` (no repository): not covered (unresolved)", summary)

    def test_emit_puts_the_heredoc_delimiter_on_its_own_line(self) -> None:
        report = {"status": "clean", "scan_conclusive": True, "changed_files_count": 0}
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / "github_output.txt"
            with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}):
                coverage._emit(report, "summary without trailing newline")
            lines = output.read_text(encoding="utf-8").splitlines()
        start = next(index for index, line in enumerate(lines) if line.startswith("summary<<"))
        delim = lines[start].split("<<", 1)[1]
        self.assertEqual(lines[start + 1], "summary without trailing newline")
        self.assertEqual(lines[start + 2], delim)

    def _changed_paths_from(self, stdout: str) -> list[tuple[str, str, str]] | None:
        result = subprocess.CompletedProcess([], 0, stdout, "")
        with patch.object(coverage.subprocess, "run", return_value=result):
            return coverage._changed_paths("base")

    def test_changed_paths_rejects_short_rename_and_copy_records(self) -> None:
        for status in ("R100", "C100"):
            with self.subTest(status=status):
                self.assertIsNone(self._changed_paths_from(f"{status}\0old-name"))

    def test_changed_paths_rejects_short_single_path_record(self) -> None:
        self.assertIsNone(self._changed_paths_from("M"))

    def test_changed_paths_reads_complete_rename_and_copy_records(self) -> None:
        self.assertEqual(
            self._changed_paths_from("R100\0old\0new\0C75\0src\0dst\0M\0other\0"),
            [("old", "new", "R"), ("src", "dst", "C"), ("other", "other", "M")],
        )


if __name__ == "__main__":
    unittest.main()


class AuthenticatedBaseFetchTest(unittest.TestCase):
    """A base commit outside the shallow clone is fetched with one-time auth."""

    def _run_fetch(self, token: str) -> list:
        calls = []

        def fake_run(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 1 if argv[1] == "rev-parse" else 0, "", "")

        with patch.object(coverage.subprocess, "run", side_effect=fake_run):
            coverage._fetch_commit("a" * 40, token)
        return calls

    def test_token_reaches_git_through_env_only(self) -> None:
        token = "ghs_" + "x" * 20
        calls = self._run_fetch(token)
        fetches = [(argv, kw) for argv, kw in calls if argv[1] == "fetch"]
        self.assertEqual(len(fetches), 1)
        argv, kwargs = fetches[0]
        self.assertNotIn(token, " ".join(argv))
        env = kwargs["env"]
        index = int(env["GIT_CONFIG_COUNT"]) - 1
        self.assertEqual(env[f"GIT_CONFIG_KEY_{index}"], "http.extraheader")
        expected = coverage.base64.b64encode(f"x-access-token:{token}".encode()).decode()
        self.assertEqual(env[f"GIT_CONFIG_VALUE_{index}"], f"AUTHORIZATION: basic {expected}")
        self.assertTrue(kwargs["capture_output"])
        for argv, _ in calls:
            self.assertNotIn(token, " ".join(argv))

    def test_existing_config_entries_are_kept(self) -> None:
        with patch.dict(os.environ, {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "a.b", "GIT_CONFIG_VALUE_0": "c"}):
            env = coverage._fetch_env("tok")
        self.assertEqual(env["GIT_CONFIG_COUNT"], "2")
        self.assertEqual(env["GIT_CONFIG_KEY_0"], "a.b")
        self.assertEqual(env["GIT_CONFIG_KEY_1"], "http.extraheader")

    def test_no_token_adds_no_header(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GIT_CONFIG_COUNT", None)
            env = coverage._fetch_env("")
        self.assertNotIn("GIT_CONFIG_COUNT", env)
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")

    def test_main_removes_token_before_child_processes(self) -> None:
        seen = {}

        def fake_plan(token=""):
            seen["token"] = token
            seen["env"] = os.environ.get(coverage.FETCH_AUTH_VARIABLE)
            raise RuntimeError("stop")

        with (
            patch.dict(os.environ, {coverage.FETCH_AUTH_VARIABLE: "tok", "DCR_OUT": "unused"}),
            patch.object(coverage, "_plan", side_effect=fake_plan),
            self.assertRaises(RuntimeError),
        ):
            coverage.main()
        self.assertEqual(seen, {"token": "tok", "env": None})
