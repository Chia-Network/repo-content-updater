"""Manifest diffs that the listed Dependabot update does not explain."""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import dependency_manifest_diff as manifest
import dependency_update_coverage as coverage
import malware_verdict_formatter as formatter
from test_dependency_update_coverage import _clean, _commit, _git

_PASS_REVIEW = "MALWARE_REVIEW_VERDICT: benign\n\nLockfile change is the listed bump.\n"
_BLOCK_REVIEW = "MALWARE_REVIEW_VERDICT: malicious\n\nDo not merge.\n"


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


def _bump(name: str, frm: str, to: str, repo: str) -> dict[str, str]:
    return {"packageName": name, "fromVersion": frm, "toVersion": to, "upstreamRepo": repo}


def _unresolved(report: dict) -> set[str]:
    return {item["package_name"] for item in report["dependencies"] if item.get("not_scanned_reason") == "unresolved"}


class DependencyManifestDiffTest(unittest.TestCase):
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

    def test_listed_registry_lock_bump_is_conclusive(self) -> None:
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
        self.assertNotIn("dependencies", report)
        published = formatter.compose_published_review(report, _PASS_REVIEW, "COMPATIBILITY_RECOMMENDATION: Merge\n")
        self.assertEqual(published["check"], "pass")
        self.assertIs(published["may_complete"], True)

    def test_listed_lock_wrong_version_label_is_unresolved(self) -> None:
        old_url = "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
        integrity = "sha512-lodash-old"
        listed = [_bump("lodash", "4.17.20", "4.17.21", "lodash/lodash")]

        def npm(version: str) -> str:
            body = {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/lodash": {
                        "version": version,
                        "resolved": old_url,
                        "integrity": integrity,
                    }
                },
            }
            return json.dumps(body) + "\n"

        def yarn(version: str) -> str:
            return (
                "lodash@^4.17.20:\n"
                f'  version "{version}"\n'
                f'  resolved "{old_url}"\n'
                f'  integrity "{integrity}"\n'
            )

        for path, render in (
            ("package-lock.json", npm),
            ("npm-shrinkwrap.json", npm),
            ("yarn.lock", yarn),
        ):
            with self.subTest(path=path):
                report = _run_listed_scan({path: render("4.17.20")}, {path: render("9.9.9")}, listed)
                self.assertFalse(report["scan_conclusive"])
                self.assertIn(path, _unresolved(report))
                published = formatter.compose_published_review(
                    report, _PASS_REVIEW, "COMPATIBILITY_RECOMMENDATION: Merge\n"
                )
                self.assertEqual(published["check"], "fail")
                self.assertIs(published["may_complete"], False)

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
                f'lodash@^4.17.20:\n  version "{version}"\n'
                f'  resolved "https://registry.yarnpkg.com/lodash/-/lodash-{version}.tgz"\n'
                f'  integrity "{integrity}"\n\n'
                f'lodash@^3.10.1:\n  version "3.10.1"\n'
                f'  resolved "https://registry.yarnpkg.com/lodash/-/lodash-3.10.1.tgz"\n'
                f'  integrity "{other}"\n'
            )

        def lock(version: str, integrity: str, nested: str) -> str:
            lodash = {
                "version": version,
                "resolved": f"https://registry.npmjs.org/lodash/-/lodash-{version}.tgz",
                "integrity": integrity,
                "dependencies": {"minimist": {"version": "1.2.8", "integrity": nested}},
            }
            return json.dumps({"lockfileVersion": 1, "dependencies": {"lodash": lodash}}) + "\n"

        listed = [_bump("lodash", "4.17.20", "4.17.21", "lodash/lodash")]
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
        self.assertNotIn("dependencies", clean)
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

        def stanza(selector: str, version: str, resolved: str) -> str:
            return f'lodash@{selector}:\n  version "{version}"\n  resolved "{resolved}"\n  integrity "sha"\n'

        base_lock = "\n".join(
            (
                stanza("^4.17.20", "4.17.20", "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz"),
                stanza("^4.0.0", "4.17.20", "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz"),
            )
        )
        head_lock = "\n".join(
            (
                stanza("^4.17.20", "4.17.21", "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"),
                stanza("^4.17.21", "4.17.21", "https://evil.example/lodash.tgz"),
            )
        )
        swap = _run_listed_scan(
            {"package.json": '{"dependencies":{"lodash":"^4.17.20"}}\n', "yarn.lock": base_lock},
            {"package.json": '{"dependencies":{"lodash":"^4.17.21"}}\n', "yarn.lock": head_lock},
            listed,
        )
        self.assertIs(swap["scan_conclusive"], False)
        self.assertNotEqual(swap["status"], "clean")

    def test_added_yarn_descriptor_at_the_listed_version_is_unresolved(self) -> None:
        updates = [_bump("lodash", "4.17.20", "4.17.21", "lodash/lodash")]
        old = (
            'lodash@^4.17.20:\n  version "4.17.20"\n'
            '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz"\n'
            '  integrity "sha-old"\n'
        )
        added = (
            'lodash@^4.17.20:\n  version "4.17.21"\n'
            '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"\n'
            '  integrity "sha-new"\n\n'
            'lodash@^4.17.21:\n  version "4.17.21"\n'
            '  resolved "https://evil.example/lodash.tgz"\n'
            '  integrity "sha-evil"\n'
        )
        self.assertFalse(manifest._entries_explain("yarn", old, added, updates))
        report = _run_listed_scan({"yarn.lock": old}, {"yarn.lock": added}, updates)
        self.assertIn("yarn.lock", {item["package_name"] for item in report["dependencies"]})
        self.assertIs(report["scan_conclusive"], False)
        self.assertNotEqual(report["status"], "clean")

    def test_duplicate_require_pin_and_warn_stay_non_clean(self) -> None:
        updates = [_bump("github.com/spf13/cobra", "v1.8.0", "v1.8.1", "spf13/cobra")]
        old_mod = "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/spf13/cobra v1.8.0\n\tgithub.com/foo/bar v1.2.3\n)\n"
        new_mod = "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/spf13/cobra v1.8.1\n\tgithub.com/foo/bar v1.9.9\n\tgithub.com/foo/bar v1.2.3\n)\n"
        report = _run_listed_scan(
            {"go.mod": old_mod, "requirements.txt": "requests==2.31.0\n"},
            {"go.mod": new_mod, "requirements.txt": "requests==9.9.9\nrequests==2.31.0\n"},
            updates,
        )
        names = {item["package_name"] for item in report["dependencies"]}
        self.assertIn("go.mod", names)
        self.assertIn("requirements.txt", names)
        self.assertIs(report["scan_conclusive"], False)
        self.assertNotEqual(report["status"], "clean")
        planted = _clean("left-pad", "left-pad/left-pad")
        planted["status"] = "warn"
        planted["findings"] = {key: [] for key in planted["findings"]}
        planted["verdict_token_in_tree"] = True
        grouped = coverage.aggregate([_clean("lodash", "lodash/lodash"), planted])
        self.assertEqual(grouped["status"], "warn")
        self.assertIs(grouped["verdict_token_in_tree"], True)

    def test_package_named_go_mod_does_not_hide_an_extra_require(self) -> None:
        base = "module example.com/app\n\ngo 1.22\n\nrequire github.com/foo/bar v1.2.3\n"
        head = (
            "module example.com/app\n\ngo 1.22\n\n"
            "require github.com/foo/bar v1.9.9\n"
            "require github.com/foo/bar v1.2.3\n"
        )
        report = _run_listed_scan(
            {"go.mod": base},
            {"go.mod": head},
            [_bump("go.mod", "1.0.0", "1.0.1", "evil/mod")],
        )
        self.assertIs(report["scan_conclusive"], False)
        self.assertNotEqual(report["status"], "clean")
        unresolved = _unresolved(report)
        self.assertIn("go.mod", unresolved)
        self.assertIn("github.com/foo/bar", unresolved)

    def test_package_named_requirements_txt_does_not_hide_a_duplicate_pin(self) -> None:
        report = _run_listed_scan(
            {"requirements.txt": "requests==2.31.0\n"},
            {"requirements.txt": "requests==9.9.9\nrequests==2.31.0\n"},
            [_bump("requirements.txt", "1.0.0", "1.0.1", "evil/mod")],
        )
        self.assertIs(report["scan_conclusive"], False)
        self.assertNotEqual(report["status"], "clean")
        unresolved = _unresolved(report)
        self.assertIn("requirements.txt", unresolved)
        self.assertIn("requests", unresolved)

    def test_listed_cobra_bump_and_package_named_go_mod_stay_unresolved(self) -> None:
        old_mod = (
            "module example.com/app\n\ngo 1.22\n\nrequire (\n"
            "\tgithub.com/spf13/cobra v1.8.0\n"
            "\tgithub.com/foo/bar v1.2.3\n)\n"
        )
        new_mod = (
            "module example.com/app\n\ngo 1.22\n\nrequire (\n"
            "\tgithub.com/spf13/cobra v1.8.1\n"
            "\tgithub.com/foo/bar v1.9.9\n"
            "\tgithub.com/foo/bar v1.2.3\n)\n"
        )
        report = _run_listed_scan(
            {"go.mod": old_mod},
            {"go.mod": new_mod},
            [
                _bump("github.com/spf13/cobra", "v1.8.0", "v1.8.1", "spf13/cobra"),
                _bump("go.mod", "1.0.0", "1.0.1", "evil/mod"),
            ],
        )
        self.assertIs(report["scan_conclusive"], False)
        self.assertNotEqual(report["status"], "clean")
        unresolved = _unresolved(report)
        self.assertIn("go.mod", unresolved)
        self.assertIn("github.com/foo/bar", unresolved)

    def test_unchanged_yarn_descriptors_are_not_named_on_an_unresolved_lock(self) -> None:
        def lock(integrity: str) -> str:
            return (
                f'lodash@^4.17.20:\n  version "4.17.20"\n  integrity "{integrity}"\n\n'
                'left-pad@^1.3.0:\n  version "1.3.0"\n  integrity "sha-a"\n\n'
                'left-pad@^1.0.0:\n  version "1.3.0"\n  integrity "sha-a"\n'
            )

        report = _run_listed_scan(
            {"yarn.lock": lock("sha-old")},
            {"yarn.lock": lock("sha-new")},
            [_bump("lodash", "4.17.20", "4.17.21", "lodash/lodash")],
        )
        names = {item["package_name"] for item in report["dependencies"]}
        self.assertIn("yarn.lock", names)
        self.assertNotIn("left-pad", names)
        self.assertIs(report["scan_conclusive"], False)
        self.assertNotEqual(report["status"], "clean")

    def test_go_sum_bump_that_keeps_old_lines_is_covered(self) -> None:
        def go_sum(*versions: tuple[str, str]) -> str:
            rows = []
            for version, digest in versions:
                rows.append(f"github.com/spf13/cobra {version} h1:{digest}")
                rows.append(f"github.com/spf13/cobra {version}/go.mod h1:{digest}")
            return "\n".join(rows) + "\n"

        old_digest = "a" * 43 + "="
        new_digest = "b" * 43 + "="
        base = go_sum(("v1.8.0", old_digest))
        head = go_sum(("v1.8.0", old_digest), ("v1.8.1", new_digest))
        updates = [_bump("github.com/spf13/cobra", "v1.8.0", "v1.8.1", "spf13/cobra")]
        report = _run_listed_scan({"go.sum": base}, {"go.sum": head}, updates)
        self.assertIs(report["scan_conclusive"], True)
        self.assertEqual(report["status"], "clean")
        self.assertEqual(report["package_name"], "github.com/spf13/cobra")
        self.assertEqual(report["not_scanned_reason"], "")
        rewritten = go_sum(("v1.8.0", "c" * 43 + "="), ("v1.8.1", new_digest))
        self.assertFalse(manifest._entries_explain("go.sum", base, rewritten, updates))
        extra = go_sum(("v1.8.0", old_digest), ("v1.8.1", new_digest), ("v1.9.0", "d" * 43 + "="))
        self.assertFalse(manifest._entries_explain("go.sum", base, extra, updates))
        both = go_sum(("v1.8.0", old_digest), ("v1.8.1", new_digest))
        self.assertTrue(manifest._entries_explain("go.sum", both, go_sum(("v1.8.1", new_digest)), updates))

    def test_mixed_case_requirement_name_is_covered(self) -> None:
        self.assertEqual(manifest._requirement_name("PyYAML"), "pyyaml")
        self.assertEqual(manifest._requirement_name("Foo_Bar.Baz"), "foo-bar-baz")
        report = _run_listed_scan(
            {"requirements.txt": "PyYAML==5.4.1\n"},
            {"requirements.txt": "PyYAML==6.0.1\n"},
            [_bump("PyYAML", "5.4.1", "6.0.1", "yaml/pyyaml")],
        )
        self.assertIs(report["scan_conclusive"], True)
        self.assertEqual(report["status"], "clean")
        self.assertEqual(report["package_name"], "PyYAML")
        self.assertEqual(report["not_scanned_reason"], "")
        separators = _run_listed_scan(
            {"requirements.txt": "Foo.Bar_Baz==1.0.0\n"},
            {"requirements.txt": "Foo.Bar_Baz==1.1.0\n"},
            [_bump("Foo_Bar.Baz", "1.0.0", "1.1.0", "example/foo-bar-baz")],
        )
        self.assertIs(separators["scan_conclusive"], True)
        self.assertEqual(separators["status"], "clean")
        self.assertEqual(separators["package_name"], "Foo_Bar.Baz")
        self.assertEqual(separators["not_scanned_reason"], "")

    def test_poetry_lock_and_transitive_residue_pass_when_the_verdict_is_pass(self) -> None:
        listed = [_bump("lodash", "4.17.20", "4.17.21", "lodash/lodash")]
        poetry = _run_listed_scan(
            {"poetry.lock": '[[package]]\nname = "lodash"\nversion = "4.17.20"\n'},
            {"poetry.lock": '[[package]]\nname = "lodash"\nversion = "4.17.21"\n'},
            listed,
        )
        self.assertIs(poetry["scan_conclusive"], True)
        self.assertEqual(poetry["status"], "clean")
        self.assertNotIn("poetry.lock", " ".join(poetry.get("errors") or []))
        published = formatter.compose_published_review(poetry, _PASS_REVIEW, "COMPATIBILITY_RECOMMENDATION: Merge\n")
        self.assertEqual(published["verdict"], "benign")
        self.assertEqual(published["check"], "pass")
        self.assertIs(published["may_complete"], True)

        def lock(lodash: str, minimist: str) -> str:
            return (
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "node_modules/lodash": {"version": lodash, "resolved": f"https://registry.npmjs.org/lodash/-/lodash-{lodash}.tgz", "integrity": "sha-" + lodash},
                            "node_modules/minimist": {"version": minimist, "resolved": f"https://registry.npmjs.org/minimist/-/minimist-{minimist}.tgz", "integrity": "sha-" + minimist},
                        },
                    }
                )
                + "\n"
            )

        residue = _run_listed_scan(
            {"package-lock.json": lock("4.17.20", "1.2.0")},
            {"package-lock.json": lock("4.17.21", "1.2.8")},
            listed,
        )
        self.assertIs(residue["scan_conclusive"], True)
        self.assertEqual(residue["status"], "clean")
        self.assertNotIn("minimist", " ".join(residue.get("errors") or []))
        published = formatter.compose_published_review(residue, _PASS_REVIEW, "COMPATIBILITY_RECOMMENDATION: Merge\n")
        self.assertEqual(published["check"], "pass")
        self.assertIs(published["may_complete"], True)
        blocked_review = formatter.compose_published_review(
            residue, _BLOCK_REVIEW, "COMPATIBILITY_RECOMMENDATION: Don't merge\n"
        )
        self.assertEqual(blocked_review["verdict"], "malicious")
        self.assertEqual(blocked_review["check"], "fail")
        self.assertIs(blocked_review["may_complete"], False)
        failed = {
            "status": "not_scanned",
            "scan_conclusive": False,
            "not_scanned_reason": "scanner_tools_missing",
            "verdict_token_in_tree": False,
            "findings": {"unicode": [], "confusable": [], "ioc": [], "heuristic": []},
        }
        scan_failed = formatter.compose_published_review(failed, _PASS_REVIEW, "COMPATIBILITY_RECOMMENDATION: Merge\n")
        self.assertEqual(scan_failed["verdict"], "scan_failed")
        self.assertEqual(scan_failed["check"], "fail")

        blocked = json.loads(json.dumps(residue))
        blocked["warn_only"] = False
        blocked["findings"]["unicode"] = [{"kind": "unicode", "file": "pkg/index.js", "line": 1, "match": "bidi"}]
        blocked_finding = formatter.compose_published_review(
            blocked, _PASS_REVIEW, "COMPATIBILITY_RECOMMENDATION: Merge\n"
        )
        self.assertEqual(blocked_finding["check"], "fail")
        self.assertIs(blocked_finding["may_complete"], False)
        advisory = json.loads(json.dumps(blocked))
        advisory["warn_only"] = True
        advisory_finding = formatter.compose_published_review(
            advisory, _PASS_REVIEW, "COMPATIBILITY_RECOMMENDATION: Merge\n"
        )
        self.assertEqual(advisory_finding["check"], "pass")
        self.assertIs(advisory_finding["may_complete"], True)

    def test_unlisted_resolved_change_stays_unresolved(self) -> None:
        def lock(lodash: str, minimist: str, resolved: str, integrity: str) -> str:
            return (
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "node_modules/lodash": {"version": lodash},
                            "node_modules/minimist": {
                                "version": minimist,
                                "resolved": resolved,
                                "integrity": integrity,
                            },
                        },
                    }
                )
                + "\n"
            )

        listed = [_bump("lodash", "4.17.20", "4.17.21", "lodash/lodash")]
        report = _run_listed_scan(
            {
                "package-lock.json": lock(
                    "4.17.20",
                    "1.2.0",
                    "https://registry.npmjs.org/minimist/-/minimist-1.2.0.tgz",
                    "sha512-old",
                )
            },
            {
                "package-lock.json": lock(
                    "4.17.21",
                    "1.2.8",
                    "https://github.com/evil/minimist/tarball/deadbeef",
                    "sha512-new",
                )
            },
            listed,
        )
        self.assertFalse(report["scan_conclusive"])
        self.assertIn("minimist", _unresolved(report))
        self.assertNotEqual(report["status"], "clean")
        published = formatter.compose_published_review(report, _PASS_REVIEW, "COMPATIBILITY_RECOMMENDATION: Merge\n")
        self.assertEqual(published["check"], "fail")
        self.assertIs(published["may_complete"], False)

    def test_real_dependabot_npm_and_yarn_lock_bumps(self) -> None:
        """Changed records from chia-docs#1138, chia-blockchain-gui#3141, and appsmith#9504."""
        prettier_old = {
            "version": "3.9.8",
            "resolved": "https://registry.npmjs.org/prettier/-/prettier-3.9.8.tgz",
            "integrity": "sha512-WRFq3Wn3WId7LLROfMLdH7xaFr2jR62wU8nLO6rQUOLOxNZUviyJQs1M0iIhLexSFy+L+w0ch66wtoO2jRjG0A==",
            "license": "MIT",
            "bin": {"prettier": "bin/prettier.cjs"},
            "engines": {"node": ">=14"},
            "funding": {"url": "https://github.com/prettier/prettier?sponsor=1"},
        }
        prettier_new = {
            **prettier_old,
            "version": "3.9.9",
            "resolved": "https://registry.npmjs.org/prettier/-/prettier-3.9.9.tgz",
            "integrity": "sha512-Z/CJHIkdujO/OtN7nXUii0Rf3VT5SRuhjBA82Xvu2XhBUgX3nhP67T0LHceBdQLex7OOFGTox+Q5Yg8Jk2Qivg==",
        }
        stylis = {
            "version": "4.4.0",
            "resolved": "https://registry.npmjs.org/stylis/-/stylis-4.4.0.tgz",
            "integrity": "sha512-5Z9ZpRzfuH6l/UAvCPAPUo3665Nk2wLaZU3x+TLHKVzIz33+sbJqbtrYoC3KD4/uVOr2Zp+L0LySezP9OHV9yA==",
            "license": "MIT",
        }
        nested = "node_modules/nano-css/node_modules/stylis"

        def npm(prettier: dict, spec: str, rollup: str, nested_meta: dict) -> str:
            return (
                json.dumps(
                    {
                        "name": "chia-docs",
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"dependencies": {"prettier": spec}},
                            "node_modules/prettier": prettier,
                            "packages/api": {"devDependencies": {"@rollup/plugin-node-resolve": rollup}},
                            nested: nested_meta,
                        },
                    }
                )
                + "\n"
            )

        listed = [_bump("prettier", "3.9.8", "3.9.9", "prettier/prettier")]
        base_npm = npm(prettier_old, "^3.9.8", "^16.0.3", stylis)
        head_npm = npm(prettier_new, "^3.9.9", "16.0.3", stylis)
        entries, residue = manifest._json_parts(base_npm)
        self.assertIn("stylis", entries)
        self.assertNotIn(nested, residue)
        report = _run_listed_scan(
            {"package-lock.json": base_npm},
            {"package-lock.json": head_npm},
            listed,
        )
        self.assertIs(report["scan_conclusive"], True)
        self.assertEqual(report["status"], "clean")
        self.assertNotIn("dependencies", report)
        published = formatter.compose_published_review(report, _PASS_REVIEW, "COMPATIBILITY_RECOMMENDATION: Merge\n")
        self.assertEqual(published["check"], "pass")

        swapped = dict(stylis, integrity="sha512-not-the-published-hash")
        tainted = _run_listed_scan(
            {"package-lock.json": base_npm},
            {"package-lock.json": npm(prettier_new, "^3.9.9", "16.0.3", swapped)},
            listed,
        )
        self.assertFalse(tainted["scan_conclusive"])
        self.assertIn("package-lock.json", _unresolved(tainted))

        yarn_old = (
            'ua-parser-js@^0.7.18:\n'
            '  version "0.7.22"\n'
            '  resolved "https://registry.npmjs.org/ua-parser-js/-/ua-parser-js-0.7.22.tgz"\n'
        )
        yarn_new = (
            'ua-parser-js@^0.7.18:\n'
            '  version "0.7.31"\n'
            '  resolved "https://registry.yarnpkg.com/ua-parser-js/-/ua-parser-js-0.7.31.tgz#649a656b191dffab4f21d5e053e27ca17cbff5c6"\n'
            '  integrity sha512-qLK/Xe9E2uzmYI3qLeOmI0tEOt+TBBQyUIAh4aAgU05FVYzeZrKUdkAZfBNVGRaHVgV0TDkdEngJSw/SyQchkQ==\n'
        )
        yarn_updates = [_bump("ua-parser-js", "0.7.22", "0.7.31", "faisalman/ua-parser-js")]
        yarn_report = _run_listed_scan({"yarn.lock": yarn_old}, {"yarn.lock": yarn_new}, yarn_updates)
        self.assertIs(yarn_report["scan_conclusive"], True)
        self.assertEqual(yarn_report["status"], "clean")
        added = yarn_new + (
            '\ncy-verify-downloads@^0.0.5:\n'
            '  version "0.0.5"\n'
            '  resolved "https://registry.yarnpkg.com/cy-verify-downloads/-/cy-verify-downloads-0.0.5.tgz#2f9c7da0f5fda125ecef2f19ca2b83b1890d3037"\n'
            '  integrity sha512-aRK7VvKG5rmDJK4hjZ27KM2oOOz0cMO7z/j4zX8qCc4ffXZS1XRJkofUY0w5u6MCB/wUsNMs03VuvkeR2tNPoQ==\n'
        )
        self.assertFalse(manifest._entries_explain("yarn", yarn_old, added, yarn_updates))
        added_report = _run_listed_scan({"yarn.lock": yarn_old}, {"yarn.lock": added}, yarn_updates)
        self.assertIs(added_report["scan_conclusive"], True)

    def test_locator_bytes_fail_closed(self) -> None:
        """Non-canonical locators stay byte-for-byte. Residue folds only bare, `^`, and `=` specs."""
        updates = [_bump("left-pad", "1.2.3", "1.2.4", "left-pad/left-pad")]
        canonical = "https://registry.npmjs.org/left-pad/-/left-pad-{}.tgz"
        evil = "https://evil.example/left-pad.tgz"
        mini = "https://registry.npmjs.org/minimist/-/minimist-1.2.5.tgz"

        def npm(version: str, resolved: str, integrity: str | None = None, **extra: object) -> str:
            entry: dict[str, object] = {"version": version, "resolved": resolved, **extra}
            if integrity is not None:
                entry["integrity"] = integrity
            return json.dumps({"lockfileVersion": 3, "packages": {"node_modules/left-pad": entry}})

        def explains(before: str, after: str, listed: list[dict] | None = None) -> bool:
            return manifest._entries_explain("json", before, after, updates if listed is None else listed)

        old = npm("1.2.3", canonical.format("1.2.3"), "sha-old", bin="bin/left-pad.js")
        self.assertTrue(explains(old, npm("1.2.4", canonical.format("1.2.4"), "sha-new", bin="bin/left-pad.js")))
        self.assertFalse(explains(npm("1.2.3", evil, "sha-old"), npm("1.2.4", evil, "sha-new")))
        self.assertFalse(explains(npm("1.2.3", "file:../pwned"), npm("1.2.4", "file:../pwned")))
        self.assertFalse(
            explains(
                npm("1.2.3", evil, "sha-old", resolution="left-pad@npm:1.2.3"),
                npm("1.2.4", "file:../pwned", "sha-new", resolution="left-pad@npm:1.2.4"),
            )
        )
        self.assertFalse(explains(npm("1.2.3", canonical.format("1.2.3")), npm("1.2.4", canonical.format("1.2.4"), "sha-new", resolution="left-pad@npm:1.2.4")))
        self.assertFalse(explains(old, npm("1.2.4", canonical.format("1.2.4"), "sha-new", bin="bin/cli.js")))
        self.assertFalse(explains(old, npm("1.2.4", canonical.format("1.2.4"), "sha-new", bin="../evil.js")))

        def residue(spec: str) -> str:
            return json.dumps({"packages": {"packages/api": {"dependencies": {"moment": spec}}}})

        self.assertTrue(manifest._residues_match("json", residue("^2.31.0"), residue("2.31.0")))
        self.assertTrue(manifest._residues_match("json", residue("=2.31.0"), residue("2.31.0")))
        self.assertFalse(manifest._residues_match("json", residue("~2.31.0"), residue("^2.31.0")))
        self.assertFalse(manifest._residues_match("json", residue("v2.31.0"), residue("2.31.0")))
        self.assertFalse(manifest._residues_match("json", residue("V2.31.0"), residue("2.31.0")))

        def v1(version: str, resolved: str, integrity: str, **extra: object) -> str:
            spec = {"version": version, "resolved": resolved, "integrity": integrity, **extra}
            return json.dumps({"lockfileVersion": 1, "dependencies": {"left-pad": spec}})

        self.assertTrue(explains(v1("1.2.3", canonical.format("1.2.3"), "sha-old"), v1("1.2.4", canonical.format("1.2.4"), "sha-new")))
        self.assertFalse(explains(v1("1.2.3", evil, "sha-old"), v1("1.2.4", evil, "sha-new")))
        self.assertFalse(explains(v1("1.2.3", canonical.format("1.2.3"), "sha-old"), v1("1.2.4", canonical.format("1.2.4"), "sha-new", scripts={"preinstall": "echo pwned"})))

        def nested(integrity: str) -> str:
            pad = {"version": "1.2.3", "resolved": canonical.format("1.2.3"), "integrity": "sha-old", "dependencies": {"minimist": {"version": "1.2.5", "resolved": mini, "integrity": integrity}}}
            return json.dumps({"lockfileVersion": 1, "dependencies": {"left-pad": pad}})

        self.assertFalse(manifest._residues_match("json", nested("sha-a"), nested("sha-b")))
        self.assertFalse(explains(nested("sha-a"), nested("sha-b")))
        yarn_old = 'left-pad@^1.2.3:\n  version "1.2.3"\n  resolved "file:../pwned"\n'
        yarn_new = 'left-pad@^1.2.3:\n  version "1.2.4"\n  resolved "file:../pwned"\n'
        self.assertFalse(manifest._entries_explain("yarn", yarn_old, yarn_new, updates))


if __name__ == "__main__":
    unittest.main()
