"""The published check fails closed for omitted findings, unread blobs, and a stored pass, under either warn-only setting."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_COMBINE = Path(__file__).resolve().parent / "dependency_cursor_review_combine_outputs.py"


def _complete_case() -> type[unittest.TestCase]:
    try:
        from test_dependency_cursor_review_complete import CombineCompleteTest
    except ImportError:
        from internal.workflowscripts.test_dependency_cursor_review_complete import CombineCompleteTest

    return CombineCompleteTest


class PublishedCheckTest(unittest.TestCase):
    def _run(self, malware: str | None, compatibility: str | None, report: dict | None = None) -> dict:
        return _complete_case()._run(self, malware, compatibility, report)

    def test_omitted_findings_fail_closed(self) -> None:
        written = self._run(
            '{"result": "MALWARE_REVIEW_VERDICT: benign\\n\\nClear.\\n"}',
            '{"result": "COMPATIBILITY_RECOMMENDATION: Merge\\n\\nFine.\\n"}',
            report={"status": "clean", "scan_conclusive": True, "verdict_token_in_tree": False},
        )
        self.assertIn("**Verdict: malicious**", written["result"])
        self.assertEqual(written["check"], "fail")
        self.assertIs(written["complete"], False)
        shaped = self._run(
            '{"result": "MALWARE_REVIEW_VERDICT: benign\\n\\nClear.\\n"}',
            '{"result": "COMPATIBILITY_RECOMMENDATION: Merge\\n\\nFine.\\n"}',
            report={
                "status": "clean",
                "scan_conclusive": True,
                "verdict_token_in_tree": False,
                "findings": [],
            },
        )
        self.assertEqual(shaped["check"], "fail")
        self.assertIs(shaped["complete"], False)

    def test_unread_shipped_blob_fails_the_check(self) -> None:
        benign = '{"result": "MALWARE_REVIEW_VERDICT: benign\\n\\nClear.\\n"}'
        merge = '{"result": "COMPATIBILITY_RECOMMENDATION: Merge\\n\\nFine.\\n"}'
        for cause in ("nul blob", "git-lfs pointer", "unreadable blob"):
            with self.subTest(cause=cause):
                written = self._run(
                    benign,
                    merge,
                    report={
                        "status": "not_scanned",
                        "scan_conclusive": False,
                        "not_scanned_reason": "incomplete_coverage",
                        "verdict_token_in_tree": False,
                        "unread": [{"file": "pkg/payload.js", "cause": cause}],
                        "findings": {"unicode": [], "confusable": [], "ioc": [], "heuristic": []},
                    },
                )
                self.assertIn("**Verdict: inconclusive**", written["result"])
                self.assertEqual(written["check"], "fail")
                self.assertIs(written["complete"], False)
        shaped = self._run(
            benign,
            merge,
            report={
                "status": "not_scanned",
                "scan_conclusive": False,
                "not_scanned_reason": "incomplete_coverage",
                "verdict_token_in_tree": False,
                "unread": "nul blob",
                "findings": {"unicode": [], "confusable": [], "ioc": [], "heuristic": []},
            },
        )
        self.assertEqual(shaped["check"], "fail")
        self.assertIs(shaped["complete"], False)

    def test_combine_reads_malicious_line_in_final_message(self) -> None:
        malware = json.dumps(
            {
                "result": "Reviewed the update.\n",
                "final_message": "Reviewed the update.\n\nMALWARE_REVIEW_VERDICT: malicious\n",
            }
        )
        written = self._run(
            malware,
            '{"result": "COMPATIBILITY_RECOMMENDATION: Merge\\n\\nFine.\\n"}',
            report={
                "status": "clean",
                "scan_conclusive": True,
                "verdict_token_in_tree": False,
                "findings": {"unicode": [], "confusable": [], "ioc": [], "heuristic": []},
            },
        )
        self.assertIn("**Verdict: malicious**", written["result"])
        self.assertEqual(written["check"], "fail")

    def _enforce(
        self,
        report: object,
        *,
        digest: str | None = None,
        drop_report: bool = False,
        stored: str | None = None,
        malware: str | None = None,
        warn_only: str | None = "0",
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = report if isinstance(report, bytes) else (json.dumps(report) + "\n").encode()
            report_path = root / "sealed-scan-report.json"
            if not drop_report:
                report_path.write_bytes(payload)
            stored_path = root / "cursor_output.json"
            if stored is not None:
                stored_path.write_text(stored, encoding="utf-8")
            if malware is not None:
                (root / "cursor_output_malware.json").write_text(malware, encoding="utf-8")
            env = os.environ.copy()
            env["DCR_SCAN_REPORT"] = str(report_path)
            env["DCR_MALWARE_JSON"] = str(root / "cursor_output_malware.json")
            env["DCR_COMPAT_JSON"] = str(root / "cursor_output_compatibility.json")
            env["DCR_COMBINED_JSON"] = str(stored_path)
            env["MALWARE_SCAN_REPORT_SHA256"] = digest if digest is not None else hashlib.sha256(payload).hexdigest()
            env.pop("MALWARE_WARN_ONLY", None)
            if warn_only is not None:
                env["MALWARE_WARN_ONLY"] = warn_only
            return subprocess.run(
                [sys.executable, "-I", str(_COMBINE), "--enforce-check"],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )

    def test_enforce_recomputes_the_sealed_report(self) -> None:
        clean = {
            "status": "clean",
            "scan_conclusive": True,
            "unread": [],
            "verdict_token_in_tree": False,
            "findings": {"unicode": [], "confusable": [], "ioc": [], "heuristic": []},
            "policy_warnings": [],
            "unchecked_upgrades": [],
            "unparsed_locks": [],
            "trusted_packages": [],
        }
        passed = self._enforce(clean, stored='{"check": "fail"}')
        self.assertEqual(passed.returncode, 0, msg=passed.stderr or passed.stdout)
        blocked = {
            **clean,
            "status": "warn",
            "findings": {
                "unicode": [{"kind": "unicode", "file": "pkg/index.js", "line": "1", "match": "bidi"}],
                "confusable": [],
                "ioc": [],
                "heuristic": [],
            },
        }
        failed = self._enforce(blocked, stored='{"check": "pass"}')
        self.assertNotEqual(failed.returncode, 0, msg=failed.stderr or failed.stdout)
        self.assertIn("did not pass", failed.stderr)
        unread = {
            **clean,
            "status": "not_scanned",
            "scan_conclusive": False,
            "not_scanned_reason": "incomplete_coverage",
            "unread": [{"file": "pkg/payload.js", "cause": "nul blob"}],
        }
        dropped = self._enforce(unread, stored='{"check": "pass"}')
        self.assertNotEqual(dropped.returncode, 0, msg=dropped.stderr or dropped.stdout)
        omitted = self._enforce(
            {"status": "clean", "scan_conclusive": True, "verdict_token_in_tree": False},
            stored='{"check": "pass"}',
        )
        self.assertNotEqual(omitted.returncode, 0)
        malformed = self._enforce(b"not-json\n", stored='{"check": "pass"}')
        self.assertNotEqual(malformed.returncode, 0)
        missing = self._enforce(clean, drop_report=True)
        self.assertNotEqual(missing.returncode, 0)
        mismatch = self._enforce(clean, digest=hashlib.sha256(b"other").hexdigest())
        self.assertNotEqual(mismatch.returncode, 0)
        self.assertIn("digest mismatch", mismatch.stderr)

    def test_enforce_reads_warn_only_once_from_the_environment(self) -> None:
        clean = {
            "status": "clean",
            "scan_conclusive": True,
            "unread": [],
            "verdict_token_in_tree": False,
            "findings": {"unicode": [], "confusable": [], "ioc": [], "heuristic": []},
            "policy_warnings": [],
            "unchecked_upgrades": [],
            "unparsed_locks": [],
            "trusted_packages": [],
        }
        finding = {"kind": "unicode", "file": "pkg/index.js", "line": "1", "match": "bidi"}
        suspicious = {**clean, "status": "warn", "findings": {**clean["findings"], "unicode": [finding]}}
        benign = json.dumps({"result": "MALWARE_REVIEW_VERDICT: benign\n\nClear.\n"})
        for value in ("1", "", None):
            with self.subTest(warn_only=value):
                advisory = self._enforce(suspicious, malware=benign, warn_only=value)
                self.assertEqual(advisory.returncode, 0, msg=advisory.stderr or advisory.stdout)
        for value in ("0", "false", "no"):
            with self.subTest(warn_only=value):
                self.assertNotEqual(self._enforce(suspicious, malware=benign, warn_only=value).returncode, 0)
        incomplete = {**clean, "status": "not_scanned", "scan_conclusive": False, "not_scanned_reason": "unresolved"}
        malicious = json.dumps({"result": "MALWARE_REVIEW_VERDICT: malicious\n\nEVIDENCE: a.js:1: beacon\n"})
        blocked = (
            ("missing verdict", {**clean, "status": "not_scanned", "scan_conclusive": False}, None),
            ("incomplete primary coverage", incomplete, benign),
            ("planted verdict line", {**clean, "verdict_token_in_tree": True}, benign),
            ("malicious verdict", clean, malicious),
        )
        for name, report, malware in blocked:
            with self.subTest(name):
                self.assertNotEqual(self._enforce(report, malware=malware, warn_only="1").returncode, 0)

    def test_enforce_keeps_malicious_final_message_without_official_parse(self) -> None:
        clean = {
            "status": "clean",
            "scan_conclusive": True,
            "unread": [],
            "verdict_token_in_tree": False,
            "findings": {"unicode": [], "confusable": [], "ioc": [], "heuristic": []},
            "policy_warnings": [],
            "unchecked_upgrades": [],
            "unparsed_locks": [],
            "trusted_packages": [],
        }
        malware = json.dumps(
            {
                "result": "Benign summary only.\n",
                "final_message": "MALWARE_REVIEW_VERDICT: malicious\n\nThe final message escalated.\n",
            }
        )
        failed = self._enforce(clean, malware=malware, stored='{"check": "pass"}')
        self.assertNotEqual(failed.returncode, 0, msg=failed.stderr or failed.stdout)
        self.assertIn("did not pass", failed.stderr)


if __name__ == "__main__":
    unittest.main()
