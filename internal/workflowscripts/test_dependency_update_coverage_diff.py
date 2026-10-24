"""coverage.main() over a real git diff: primaries are scanned, the rest is disclosed, decide() publishes the result."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import subprocess
import sys
import unittest
from collections.abc import Callable
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import dependency_update_coverage as coverage
import malware_verdict_formatter as formatter
from test_dependency_update_coverage import _clean, _commit, _git, _git_repo

_SCRIPTS = Path(__file__).resolve().parent
_BENIGN = "MALWARE_REVIEW_VERDICT: benign\n\nNo issues.\n"
_MERGE = "COMPATIBILITY_RECOMMENDATION: Merge\n\nFine.\n"
_WORKFLOW = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@{}\n"


def _package(dependencies: dict[str, str]) -> str:
    return json.dumps({"name": "app", "dependencies": dependencies}, indent=2) + "\n"


def _lock(versions: dict[str, str]) -> str:
    tarball = "https://registry.npmjs.org/{0}/-/{0}-{1}.tgz"
    copies = {f"node_modules/{n}": {"version": v, "resolved": tarball.format(n, v)} for n, v in versions.items()}
    packages = {"": {"name": "app"}, **copies}
    return json.dumps({"name": "app", "lockfileVersion": 3, "packages": packages}, indent=2) + "\n"


class _Diff(unittest.TestCase):
    """A repository whose main branch holds `base` and whose checked-out pr branch holds `head`."""

    def setUp(self) -> None:
        self.root = Path(self.enterContext(TemporaryDirectory())) / "repo"
        _git_repo(self.root)
        self.scanned: list[dict] = []

    def run_main(
        self,
        base: dict[str, str],
        head: dict[str, str],
        *,
        fetch: dict[str, bytes] | None = None,
        scan: Callable[..., dict] | None = None,
    ) -> tuple[dict, str]:
        """(report, summary). `fetch` answers registry URLs; the default scan records each update and is clean."""
        for path, text in base.items():
            _commit(self.root, path, text, f"base {path}")
        base_sha = _git(self.root, "rev-parse", "HEAD")
        _git(self.root, "checkout", "-q", "-b", "pr")
        for path, text in head.items():
            if base.get(path) != text:
                _commit(self.root, path, text, f"head {path}")

        def clean_scan(update: dict, *_args: object) -> dict:
            self.scanned.append(update)
            record = _clean(update["packageName"], update["upstreamRepo"])
            return {**record, "from_version": update["fromVersion"], "to_version": update["toVersion"]}

        answers = fetch or {}

        out = self.root.parent / "out"
        out.mkdir(exist_ok=True)
        variables = {"PR_BASE_SHA": base_sha, "DCR_OUT": str(out), "GITHUB_OUTPUT": str(out / "github_output.txt")}
        with (
            contextlib.chdir(self.root),
            patch.dict(os.environ, variables),
            patch.object(coverage._ecosystems.upstream, "_fetch", lambda url: answers.get(url, b"")),
            patch.object(coverage, "_scan_one", scan or clean_scan),
        ):
            os.environ.pop("GITHUB_BASE_REF", None)
            coverage.main()
        report = json.loads((out / "malware_scan_report.json").read_text(encoding="utf-8"))
        return report, (out / "malware_scan_summary.md").read_text(encoding="utf-8")


class PolicyTest(_Diff):
    def _moving(self, old: str, new: str) -> None:
        report, summary = self.run_main(
            {".github/workflows/ci.yml": _WORKFLOW.format(old)},
            {".github/workflows/ci.yml": _WORKFLOW.format(new)},
        )
        self.assertEqual(self.scanned, [])
        self.assertEqual(report["not_scanned_reason"], coverage.NOTHING_TO_SCAN)
        change = {"ecosystem": "github-actions", "dir": ".github/workflows", "name": "actions/checkout"}
        self.assertEqual(report["policy_warnings"], [{**change, "old": old, "new": new, "reason": "moving_ref"}])
        self.assertIn(
            f"- Not scanned by policy: github-actions `actions/checkout {old} -> {new}` in "
            "`.github/workflows` (`moving_ref`)",
            summary,
        )
        for warn_only in (True, False):
            published = formatter.compose_published_review({**report, "warn_only": warn_only}, _BENIGN, _MERGE)
            self.assertEqual((published["verdict"], published["check"]), ("inconclusive", "pass"))
            self.assertIn(formatter._POLICY_WARNINGS["moving_ref"], published["malware_text"])

    def test_a_moving_major_action_tag_is_inconclusive_with_a_named_warning_and_passes(self) -> None:
        self._moving("v4", "v5")

    def test_a_major_minor_action_tag_is_a_moving_ref_too(self) -> None:
        self._moving("v4.1", "v4.2")

    def test_a_full_action_tag_is_scanned_from_the_action_repository(self) -> None:
        report, _summary = self.run_main(
            {".github/workflows/ci.yml": _WORKFLOW.format("v4.1.0")},
            {".github/workflows/ci.yml": _WORKFLOW.format("v4.2.0")},
        )
        self.assertEqual(
            self.scanned,
            [
                {
                    "packageName": "actions/checkout",
                    "fromVersion": "4.1.0",
                    "toVersion": "4.2.0",
                    "upstreamRepo": "actions/checkout",
                }
            ],
        )
        self.assertEqual(report["policy_warnings"], [])
        self.assertIs(report["scan_conclusive"], True)
        published = formatter.compose_published_review(report, _BENIGN, _MERGE)
        self.assertEqual((published["verdict"], published["check"]), ("benign", "pass"))

    def test_docker_and_terraform_beside_a_clean_scan_are_never_benign(self) -> None:
        lock = 'provider "registry.terraform.io/hashicorp/aws" {{\n  version = "{}"\n}}\n'
        report, summary = self.run_main(
            {
                "Dockerfile": "FROM node:20.10\n",
                ".terraform.lock.hcl": lock.format("5.30.0"),
                "go.mod": "require github.com/a/b v1.0.0\n",
            },
            {
                "Dockerfile": "FROM node:20.11\n",
                ".terraform.lock.hcl": lock.format("5.31.0"),
                "go.mod": "require github.com/a/b v1.0.1\n",
            },
        )
        self.assertEqual([update["upstreamRepo"] for update in self.scanned], ["a/b"])
        self.assertEqual(
            {(item["ecosystem"], item["reason"]) for item in report["policy_warnings"]},
            {("docker", "unscannable_ecosystem"), ("terraform", "unscannable_ecosystem")},
        )
        self.assertIn("`node 20.10 -> 20.11`", summary)
        published = formatter.compose_published_review(report, _BENIGN, _MERGE)
        self.assertEqual((published["verdict"], published["check"]), ("inconclusive", "pass"))

    def test_a_policy_warning_never_clears_a_gap(self) -> None:
        report, _summary = self.run_main(
            {".github/workflows/ci.yml": _WORKFLOW.format("v4"), "Cargo.toml": '[dependencies]\nserde = "1.0.1"\n'},
            {".github/workflows/ci.yml": _WORKFLOW.format("v5"), "Cargo.toml": '[dependencies]\nserde = "1.0.2"\n'},
        )
        self.assertIs(report["scan_conclusive"], False)
        published = formatter.compose_published_review({**report, "warn_only": True}, _BENIGN, _MERGE)
        self.assertEqual((published["verdict"], published["check"]), ("inconclusive", "fail"))


class UncheckedUpgradeTest(_Diff):
    def test_other_upgraded_packages_are_listed_and_do_not_block(self) -> None:
        report, summary = self.run_main(
            {
                "package.json": _package({"lodash": "^4.17.20"}),
                "package-lock.json": _lock({"lodash": "4.17.20", "qs": "6.5.2", "ms": "2.1.2"}),
            },
            {
                "package.json": _package({"lodash": "^4.17.21"}),
                "package-lock.json": _lock({"lodash": "4.17.21", "qs": "6.5.3", "ms": "2.1.3"}),
            },
        )
        self.assertEqual([(u["packageName"], u["toVersion"]) for u in self.scanned], [])
        self.assertEqual(report["not_scanned_reason"], "no_upstream_link")
        self.assertEqual(
            report["unchecked_upgrades"],
            [
                {"ecosystem": "npm", "dir": ".", "name": "ms", "old": "2.1.2", "new": "2.1.3"},
                {"ecosystem": "npm", "dir": ".", "name": "qs", "old": "6.5.2", "new": "6.5.3"},
            ],
        )
        self.assertIn("- 2 other packages were upgraded and were not checked by this run:", summary)
        self.assertIn("  - npm `qs 6.5.2 -> 6.5.3` in `.`", summary)

    def test_unchecked_upgrades_beside_a_clean_scan_keep_the_verdict(self) -> None:
        report, summary = self.run_main(
            {
                "package.json": _package({"lodash": "^4.17.20"}),
                "package-lock.json": _lock({"lodash": "4.17.20", "qs": "6.5.2"}),
            },
            {
                "package.json": _package({"lodash": "^4.17.21"}),
                "package-lock.json": _lock({"lodash": "4.17.21", "qs": "6.5.3"}),
            },
            fetch={"https://registry.npmjs.org/lodash/4.17.21": b'{"repository": "github:lodash/lodash"}'},
        )
        self.assertEqual([(u["packageName"], u["upstreamRepo"]) for u in self.scanned], [("lodash", "lodash/lodash")])
        self.assertIn("- 1 other package was upgraded and was not checked by this run:", summary)
        published = formatter.compose_published_review(report, _BENIGN, _MERGE)
        self.assertEqual((published["verdict"], published["check"]), ("benign", "pass"))

    def test_a_transitive_only_bump_scans_nothing_and_does_not_block(self) -> None:
        report, summary = self.run_main(
            {
                "package.json": _package({"express": "^4.18.0"}),
                "package-lock.json": _lock({"express": "4.18.2", "qs": "6.5.2"}),
            },
            {
                "package.json": _package({"express": "^4.18.0"}),
                "package-lock.json": _lock({"express": "4.18.2", "qs": "6.5.3"}),
            },
        )
        self.assertEqual(self.scanned, [])
        self.assertEqual((report["not_scanned_reason"], report["errors"]), (coverage.NOTHING_TO_SCAN, []))
        self.assertIn("1 other package was upgraded", summary)
        published = formatter.compose_published_review(report, _BENIGN, _MERGE)
        self.assertEqual((published["verdict"], published["check"]), ("inconclusive", "pass"))
        self.assertIn(formatter._NOTHING_SCANNED, published["malware_text"])

    def test_an_empty_diff_is_incomplete_coverage(self) -> None:
        report, _summary = self.run_main({"go.sum": "a\n"}, {"go.sum": "b\n"})
        self.assertEqual(report["not_scanned_reason"], "incomplete_coverage")
        self.assertEqual(formatter.compose_published_review(report, _BENIGN, _MERGE)["check"], "fail")


class BaseCommitTest(_Diff):
    def _gaps(self, **env: str) -> list[tuple[str, str]] | None:
        _commit(self.root, "requirements.txt", "requests==2.31.0\n", "base")
        _git(self.root, "checkout", "-q", "-b", "pr")
        _commit(self.root, "requirements.txt", "requests==2.32.0\n", "bump")
        with contextlib.chdir(self.root), patch.dict(os.environ, env):
            for name in ("PR_BASE_SHA", "GITHUB_BASE_REF"):
                if name not in env:
                    os.environ.pop(name, None)
            plan = coverage._plan()
        return None if plan is None else list(plan.gaps)

    def test_an_unnamed_or_unreadable_base_has_no_plan(self) -> None:
        self.assertIsNone(self._gaps())

    def test_an_unreadable_named_base_has_no_plan(self) -> None:
        self.assertIsNone(self._gaps(PR_BASE_SHA="abc123"))

    def test_a_named_base_ref_resolves(self) -> None:
        self.assertEqual(self._gaps(GITHUB_BASE_REF="main"), [])

    def test_a_worktree_git_file_resolves_the_named_base(self) -> None:
        _commit(self.root, "requirements.txt", "requests==2.31.0\n", "base")
        base = _git(self.root, "rev-parse", "HEAD")
        _commit(self.root, "requirements.txt", "requests==2.32.0\n", "bump")
        worktree = self.root.parent / "wt"
        _git(self.root, "worktree", "add", "--detach", "-q", str(worktree), "HEAD")
        self.assertTrue((worktree / ".git").is_file())
        with contextlib.chdir(worktree), patch.dict(os.environ, {"PR_BASE_SHA": base}):
            os.environ.pop("GITHUB_BASE_REF", None)
            plan = coverage._plan()
        self.assertIsNotNone(plan)
        self.assertEqual([change.name for change in plan.primary], ["requests"])


class PublishedStatusTest(_Diff):
    """The PR comment carries one status: the verdict decide() wrote. The scan summary holds coverage facts only."""

    def test_strict_findings_post_the_decided_verdict_and_no_scan_status(self) -> None:
        source = b'{"info": {"project_urls": {"Source": "https://github.com/psf/requests"}}}'
        finding = {"file": "src/client.py", "line": 3, "kind": "network_beacon", "match": "beacon()"}
        findings = {"unicode": [], "confusable": [], "ioc": [], "heuristic": [finding]}

        def strict_warn(update: dict, *_args: object) -> dict:
            return {
                **_clean("requests", update["upstreamRepo"]),
                "status": "warn",
                "warn_only": False,
                "findings": findings,
            }

        report, summary = self.run_main(
            {"requirements.txt": "requests==2.31.0\n"},
            {"requirements.txt": "requests==2.32.0\n"},
            fetch={"https://pypi.org/pypi/requests/2.32.0/json": source},
            scan=strict_warn,
        )
        self.assertEqual(report["status"], "warn")
        self.assertNotIn("Status:", summary)
        body = self._comment(report, summary)
        self.assertIn("**Verdict: suspicious**", body)
        self.assertIn("`src/client.py:3` beacon()", body)
        self.assertNotIn("Status:", body)
        self.assertNotIn("warn**", body)

    def _comment(self, report: dict, summary: str) -> str:
        """Run combine and the post-comment script the way the verdict job does, and return the posted body."""
        work = self.root.parent / "verdict"
        (work / "dcr-scan-input").mkdir(parents=True)
        payload = (json.dumps(report) + "\n").encode()
        (work / "dcr-scan-input" / "malware_scan_report.json").write_bytes(payload)
        (work / "dcr-scan-input" / "malware_scan_summary.md").write_text(summary, encoding="utf-8")
        (work / "cursor_output_malware.json").write_text(json.dumps({"result": _BENIGN}), encoding="utf-8")
        (work / "cursor_output_compatibility.json").write_text(json.dumps({"result": _MERGE}), encoding="utf-8")
        env = {
            **os.environ,
            "MALWARE_SCAN_REPORT_SHA256": hashlib.sha256(payload).hexdigest(),
            "DCR_SCAN_REPORT": str(work / "dcr-scan-input" / "malware_scan_report.json"),
            "DCR_MALWARE_JSON": str(work / "cursor_output_malware.json"),
            "DCR_COMPAT_JSON": str(work / "cursor_output_compatibility.json"),
            "DCR_COMBINED_JSON": str(work / "cursor_output.json"),
            "MALWARE_SCAN_STATUS": "warn",
            "PR_NUMBER": "7",
        }
        combine = _SCRIPTS / "dependency_cursor_review_combine_outputs.py"
        subprocess.run([sys.executable, "-I", str(combine)], cwd=work, env=env, check=True, capture_output=True)
        script = (
            f"const run = require({json.dumps(str(_SCRIPTS / 'dependency-cursor-review-post-comment.js'))});"
            "const posted = [];"
            "const github = {paginate: async () => [], rest: {issues: {listComments() {},"
            " createComment: async (args) => posted.push(args.body), updateComment: async () => {}}}};"
            "run({github, context: {repo: {owner: 'o', repo: 'r'}}, core: {info() {}}})"
            ".then(() => process.stdout.write(posted[0]));"
        )
        proc = subprocess.run(["node", "-e", script], cwd=work, env=env, check=True, capture_output=True, text=True)
        return proc.stdout


if __name__ == "__main__":
    unittest.main()
