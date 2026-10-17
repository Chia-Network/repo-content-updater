"""A real scanner report is the input to the published review."""

from __future__ import annotations

import os
from pathlib import Path

try:
    from malware_verdict_formatter import compose_published_review
    from upstream_malware_scan_case import UpstreamScanCase, _commit_file, _git
except ImportError:
    from internal.workflowscripts.malware_verdict_formatter import compose_published_review
    from internal.workflowscripts.upstream_malware_scan_case import (
        UpstreamScanCase,
        _commit_file,
        _git,
    )

_LIB = Path(__file__).resolve().parent / "upstream_malware_scan_lib.sh"
_BENIGN = "MALWARE_REVIEW_VERDICT: benign\n\nNo issues.\n"
_MERGE = "COMPATIBILITY_RECOMMENDATION: Merge\n\nCall sites are unchanged.\n"


def _shell_int(name: str) -> int:
    for line in _LIB.read_text(encoding="utf-8").splitlines():
        if line.startswith(f"{name}="):
            return int(line.split("=", 1)[1].strip())
    raise AssertionError(f"missing {name}")


def _public(report: dict) -> dict:
    return {key: value for key, value in report.items() if not str(key).startswith("_")}


class ScanPublishedReviewTest(UpstreamScanCase):
    def test_tag_spellings_disagree_stays_suspicious(self) -> None:
        with self._workspace() as (work, repo):
            _commit_file(repo, "pkg/index.js", "module.exports = 1;\n", "one")
            _git(repo, "tag", "1.1.0")
            _commit_file(repo, "pkg/index.js", "module.exports = 2;\n", "other")
            _git(repo, "tag", "v1.1.0")
            report = self._scan(work, repo, FROM_VERSION="1.0.0", TO_VERSION="1.1.0")
            self.assertNotEqual(report["status"], "clean", msg=report)
            self.assertFalse(report["scan_conclusive"])
            self.assertEqual(report["not_scanned_reason"], "tag_spellings_disagree")
            published = compose_published_review(_public(report), _BENIGN, _MERGE)
            self.assertEqual(published["verdict"], "suspicious")
            self.assertIs(published["may_complete"], False)
            self.assertIn("tag_spellings_disagree", published["malware_text"])
            self.assertIn("**Verdict: suspicious**", published["malware_text"])
            self.assertNotIn("**Verdict: benign**", published["malware_text"])
            self.assertIn("**Merge**", published["compatibility_text"])

    def test_over_cap_file_and_ioc_stay_malicious(self) -> None:
        cap = _shell_int("MAX_BLOB_BYTES")
        with self._workspace() as (work, repo):
            _commit_file(repo, "pkg/index.js", "module.exports = 1;\n", "base")
            _git(repo, "tag", "v1.0.0")
            payload = repo / "lib" / "payload.bin"
            payload.parent.mkdir(parents=True)
            payload.write_bytes(b"")
            os.truncate(payload, cap + 1)
            _git(repo, "add", "lib/payload.bin")
            _git(repo, "commit", "-m", "add blob over cap")
            _commit_file(
                repo,
                "pkg/index.js",
                "const marker = 'SCAN_PUBLISHED_IOC_MARKER';\n",
                "ioc",
            )
            _git(repo, "tag", "v1.1.0")
            report = self._scan(
                work,
                repo,
                FROM_VERSION="1.0.0",
                TO_VERSION="1.1.0",
                MALWARE_IOC_PATTERNS='["SCAN_PUBLISHED_IOC_MARKER"]',
            )
            self.assertNotEqual(report["status"], "clean", msg=report)
            self.assertFalse(report["scan_conclusive"], msg=report)
            self.assertEqual(report["not_scanned_reason"], "incomplete_coverage")
            self.assertIn({"file": "lib/payload.bin", "cause": "blob over size cap"}, report["unread"])
            self.assertIn("pkg/index.js", {item["file"] for item in report["findings"]["ioc"]})
            published = compose_published_review(_public(report), _BENIGN, _MERGE)
            text = str(published["malware_text"])
            self.assertEqual(published["verdict"], "malicious")
            self.assertIs(published["may_complete"], False)
            self.assertIn("`lib/payload.bin:1`", text)
            self.assertIn("`pkg/index.js:", text)
            self.assertLess(text.index("`lib/payload.bin:1`"), text.index("`pkg/index.js:"))
            self.assertNotIn("**Verdict: benign**", text)
            self.assertIn("withheld", published["compatibility_text"])
            self.assertNotIn("**Merge**", published["compatibility_text"])
