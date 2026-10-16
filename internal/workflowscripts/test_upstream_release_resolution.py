"""Fixtures for release resolution and split-signature scans."""

from __future__ import annotations

import os
import shutil

try:
    from upstream_malware_scan_case import UpstreamScanCase, _commit_file, _git
except ImportError:
    from internal.workflowscripts.upstream_malware_scan_case import (
        UpstreamScanCase,
        _commit_file,
        _git,
    )


def _assert_not_benign(test: UpstreamScanCase, report: dict) -> None:
    test.assertEqual(report["_returncode"], 0, msg=report.get("_stderr"))
    test.assertNotEqual(report["status"], "clean", msg=report)
    test.assertFalse(report["scan_conclusive"], msg=report)
    test.assertNotIn("Status: **clean**", report["_summary"])
    summary = report["_summary"]
    test.assertTrue(
        "not evidence the package is benign" in summary
        or "not a benign result" in summary,
        msg=summary,
    )
    test.assertNotIn("Changed node/vendor paths: `0`", summary)
    test.assertIn("Release path comparison: not available", summary)


class ReleaseResolutionTest(UpstreamScanCase):
    def test_from_side_spellings_disagree(self) -> None:
        with self._workspace() as (work, repo):
            _commit_file(repo, "pkg/index.js", "module.exports = 1;\n", "bare from")
            _git(repo, "tag", "1.0.0")
            _commit_file(repo, "pkg/index.js", "module.exports = 2;\n", "prefixed from")
            _git(repo, "tag", "v1.0.0")
            _commit_file(
                repo,
                "pkg/index.js",
                "const marker = 'TO_TREE_MARKER';\n",
                "to",
            )
            _git(repo, "tag", "v1.1.0")
            report = self._scan(
                work,
                repo,
                FROM_VERSION="v1.0.0",
                TO_VERSION="1.1.0",
                MALWARE_IOC_PATTERNS='["TO_TREE_MARKER"]',
            )
            _assert_not_benign(self, report)
            self.assertEqual(report["not_scanned_reason"], "tag_spellings_disagree")
            self.assertIn(
                "pkg/index.js", {item["file"] for item in report["findings"]["ioc"]}
            )

    def test_prefixed_version_does_not_ignore_the_bare_tag(self) -> None:
        with self._workspace() as (work, repo):
            _commit_file(repo, "pkg/index.js", "module.exports = 1;\n", "from")
            _git(repo, "tag", "v1.0.0")
            _commit_file(repo, "pkg/index.js", "module.exports = 2;\n", "prefixed to")
            _git(repo, "tag", "v1.1.0")
            _commit_file(
                repo,
                "pkg/index.js",
                "const marker = 'BARE_TAG_MARKER';\n",
                "bare to",
            )
            _git(repo, "tag", "1.1.0")
            report = self._scan(
                work,
                repo,
                FROM_VERSION="v1.0.0",
                TO_VERSION="v1.1.0",
                MALWARE_IOC_PATTERNS='["BARE_TAG_MARKER"]',
            )
            _assert_not_benign(self, report)
            self.assertEqual(report["not_scanned_reason"], "tag_spellings_disagree")
            self.assertEqual(report["resolved_to"], "")

    def test_missing_from_tag_is_not_a_conclusive_scan(self) -> None:
        with self._workspace() as (work, repo):
            _commit_file(
                repo,
                "pkg/index.js",
                "const marker = 'MISSING_FROM_MARKER';\n",
                "to",
            )
            _git(repo, "tag", "v1.1.0")
            report = self._scan(
                work,
                repo,
                FROM_VERSION="9.9.9",
                TO_VERSION="1.1.0",
                MALWARE_IOC_PATTERNS='["MISSING_FROM_MARKER"]',
            )
            _assert_not_benign(self, report)
            self.assertEqual(report["not_scanned_reason"], "from_ref_unresolved")
            self.assertIn(
                "pkg/index.js", {item["file"] for item in report["findings"]["ioc"]}
            )

    def test_line_separators_do_not_hide_a_signature(self) -> None:
        blobs = {
            "pkg/vt.js": b"SPLIT" + b"\v" + b"MARKER\n",
            "pkg/ff.js": b"SPLIT" + b"\f" + b"MARKER\n",
            "pkg/ls.js": "SPLIT\u2028MARKER\n".encode(),
            "pkg/nel.js": b"SPLIT" + b"\xc2\x85" + b"MARKER\n",
        }
        with self._workspace() as (work, repo):
            _commit_file(repo, "pkg/index.js", "module.exports = 1;\n", "base")
            _git(repo, "tag", "v1.0.0")
            for rel, payload in blobs.items():
                path = repo / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
            _git(repo, "add", *blobs)
            _git(repo, "commit", "-m", "split signatures")
            _git(repo, "tag", "v1.1.0")
            report = self._scan(
                work,
                repo,
                FROM_VERSION="1.0.0",
                TO_VERSION="1.1.0",
                MALWARE_IOC_PATTERNS='["SPLITMARKER"]',
            )
            self.assertEqual(report["_returncode"], 0, msg=report["_stderr"])
            self.assertEqual(report["status"], "warn", msg=report)
            self.assertTrue(report["scan_conclusive"], msg=report)
            self.assertIn("- Status: **warn**", report["_summary"])
            self.assertNotIn("Status: **clean**", report["_summary"])
            files = {item["file"] for item in report["findings"]["ioc"]}
            self.assertEqual(files, set(blobs), msg=report["findings"]["ioc"])

    def test_allowlisted_line_does_not_hide_a_split_signature(self) -> None:
        with self._workspace() as (work, repo):
            _commit_file(repo, "pkg/index.js", "module.exports = 1;\n", "base")
            _git(repo, "tag", "v1.0.0")
            path = repo / "pkg" / "both.js"
            path.write_bytes(b"EVILTOKEN\nEVIL\vTOKEN\n")
            _git(repo, "add", "pkg/both.js")
            _git(repo, "commit", "-m", "line and split")
            _git(repo, "tag", "v1.1.0")
            report = self._scan(
                work,
                repo,
                FROM_VERSION="1.0.0",
                TO_VERSION="1.1.0",
                MALWARE_IOC_PATTERNS='["EVILTOKEN"]',
                MALWARE_IOC_ALLOWLIST='["pkg/both.js:1:"]',
            )
            self.assertEqual(report["_returncode"], 0, msg=report["_stderr"])
            self.assertEqual(report["status"], "warn", msg=report)
            self.assertTrue(report["scan_conclusive"], msg=report)
            self.assertIn("- Status: **warn**", report["_summary"])
            self.assertNotIn("Status: **clean**", report["_summary"])
            hits = [
                item
                for item in report["findings"]["ioc"]
                if item["file"] == "pkg/both.js"
            ]
            self.assertTrue(hits, msg=report["findings"]["ioc"])
            self.assertTrue(all(item["line"] == 0 for item in hits), msg=hits)

    def test_release_diff_failure_is_not_conclusive(self) -> None:
        with self._workspace() as (work, repo):
            _commit_file(repo, "pkg/index.js", "module.exports = 1;\n", "base")
            _git(repo, "tag", "v1.0.0")
            _commit_file(repo, "pkg/index.js", "module.exports = 2;\n", "next")
            _git(repo, "tag", "v1.1.0")
            real_git = shutil.which("git")
            self.assertIsNotNone(real_git)
            bin_dir = work / "bin"
            bin_dir.mkdir()
            wrapper = bin_dir / "git"
            wrapper.write_text(
                "#!/bin/sh\n"
                'for arg in "$@"; do\n'
                '  if [ "$arg" = diff ]; then\n'
                "    exit 2\n"
                "  fi\n"
                "done\n"
                f'exec {real_git} "$@"\n',
                encoding="utf-8",
            )
            wrapper.chmod(0o755)
            report = self._scan(
                work,
                repo,
                FROM_VERSION="1.0.0",
                TO_VERSION="1.1.0",
                PATH=f"{bin_dir}:{os.environ.get('PATH', '')}",
            )
            _assert_not_benign(self, report)
            self.assertEqual(report["not_scanned_reason"], "incomplete_coverage")
            self.assertTrue(
                any(err == "release diff failed" for err in report["errors"]),
                msg=report["errors"],
            )

    def test_newline_in_diff_path_is_not_conclusive(self) -> None:
        with self._workspace() as (work, repo):
            _commit_file(repo, "pkg/index.js", "module.exports = 1;\n", "base")
            _git(repo, "tag", "v1.0.0")
            rel = "pkg/evil\nname.js"
            path = repo / "pkg" / "evil\nname.js"
            path.write_text("module.exports = 2;\n", encoding="utf-8")
            _git(repo, "add", "--", rel)
            _git(repo, "commit", "-m", "newline name")
            _git(repo, "tag", "v1.1.0")
            report = self._scan(
                work,
                repo,
                FROM_VERSION="1.0.0",
                TO_VERSION="1.1.0",
            )
            _assert_not_benign(self, report)
            self.assertEqual(report["not_scanned_reason"], "incomplete_coverage")
            self.assertTrue(
                any("release diff path not scored" in err for err in report["errors"]),
                msg=report["errors"],
            )
