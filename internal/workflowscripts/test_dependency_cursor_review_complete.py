"""complete is true only when both Cursor outputs are real analyses."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent

import formatter_runtime_bundle as _runtime  # noqa: E402

_BUNDLE_STEMS = (
    *_runtime.FORMATTER_RUNTIME_FILENAMES,
    *_runtime.DCR_COMBINE_EXTRA_FILENAMES,
)
_COMBINE = _SCRIPTS / "dependency_cursor_review_combine_outputs.py"


class CombineCompleteTest(unittest.TestCase):
    def _run(
        self,
        malware: str | None,
        compatibility: str | None,
        report: dict | None = None,
    ) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts = root / ".github" / "scripts"
            scripts.mkdir(parents=True)
            for name in _BUNDLE_STEMS:
                shutil.copy2(_SCRIPTS / name, scripts / name)
            if malware is not None:
                (root / "cursor_output_malware.json").write_text(malware, encoding="utf-8")
            if compatibility is not None:
                (root / "cursor_output_compatibility.json").write_text(
                    compatibility, encoding="utf-8"
                )
            if report is None:
                report = {
                    "status": "clean",
                    "scan_conclusive": True,
                    "verdict_token_in_tree": False,
                }
            payload = (json.dumps(report) + "\n").encode()
            report_path = root / "sealed-scan-report.json"
            report_path.write_bytes(payload)
            env = os.environ.copy()
            env["DCR_SCAN_REPORT"] = str(report_path)
            env["DCR_MALWARE_JSON"] = str(root / "cursor_output_malware.json")
            env["DCR_COMPAT_JSON"] = str(root / "cursor_output_compatibility.json")
            env["DCR_COMBINED_JSON"] = str(root / "cursor_output.json")
            env["MALWARE_SCAN_REPORT_SHA256"] = hashlib.sha256(payload).hexdigest()
            proc = subprocess.run(
                [sys.executable, "-I", str(_COMBINE)],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
            return json.loads((root / "cursor_output.json").read_text(encoding="utf-8"))

    def test_both_files_missing(self) -> None:
        self.assertIs(self._run(None, None)["complete"], False)

    def test_empty_files(self) -> None:
        self.assertIs(self._run("", "")["complete"], False)

    def test_plain_text_agent_exit(self) -> None:
        text = "Error: agent exited"
        self.assertIs(self._run(text, text)["complete"], False)

    def test_result_string_agent_exit(self) -> None:
        payload = '{"result": "Error: agent exited with code 1"}'
        self.assertIs(self._run(payload, payload)["complete"], False)

    def test_is_error_result(self) -> None:
        payload = '{"type":"result","is_error":true,"result":"agent failed"}'
        self.assertIs(self._run(payload, payload)["complete"], False)

    def test_json_without_analysis_string(self) -> None:
        payload = '{"type":"result","duration_ms":1}'
        written = self._run(payload, payload)
        self.assertIs(written["complete"], False)
        self.assertIn("duration_ms", written["result"])

    def test_both_files_with_errors(self) -> None:
        error = '{"error": "model failed"}'
        self.assertIs(self._run(error, error)["complete"], False)

    def test_one_good_and_one_bad(self) -> None:
        written = self._run(
            '{"result": "Verdict: benign"}',
            '{"error": "model failed"}',
        )
        self.assertIs(written["complete"], False)

    def test_skipped_api_key_is_incomplete(self) -> None:
        payload = '{"result":"CURSOR_API_KEY is not set; analysis was skipped.","complete":false}'
        self.assertIs(self._run(payload, payload)["complete"], False)

    def test_both_good(self) -> None:
        written = self._run(
            '{"result": "Verdict: benign"}',
            '{"result": "compat ok"}',
        )
        self.assertIs(written["complete"], True)

    def test_not_scanned_without_findings_stays_blocking(self) -> None:
        written = self._run(
            '{"result": "MALWARE_REVIEW_VERDICT: benign\\n\\nNo IOCs.\\n\\n**Verdict: benign**"}',
            '{"result": "compat ok"}',
            report={
                "status": "not_scanned",
                "scan_conclusive": False,
                "verdict_token_in_tree": False,
            },
        )
        self.assertIn("**Verdict: malicious**", written["result"])
        self.assertNotIn("**Verdict: benign**", written["result"])
        self.assertNotIn("No IOCs.", written["result"])
        self.assertNotIn("compat ok", written["result"])
        self.assertIn("Compatibility recommendation withheld", written["result"])
        self.assertNotIn("needs human review", written["result"])
        self.assertIs(written["complete"], True)
        self.assertNotIn("**Verdict: benign**", json.dumps(written["malware_review"]))

    def test_findings_drop_agent_benign_verdict(self) -> None:
        written = self._run(
            '{"result": "MALWARE_REVIEW_VERDICT: benign\\n\\n**Verdict: benign**"}',
            '{"result": "compat essay"}',
            report={
                "status": "warn",
                "scan_conclusive": True,
                "verdict_token_in_tree": False,
                "findings": {
                    "ioc": [{"file": "pkg/index.js"}],
                    "unicode": [],
                    "confusable": [],
                    "heuristic": [],
                },
            },
        )
        self.assertIn("**Verdict: malicious**", written["result"])
        self.assertNotIn("**Verdict: benign**", written["result"])
        self.assertNotIn("compat essay", written["result"])
        self.assertNotIn("needs human review", written["result"])
        self.assertIs(written["complete"], True)

    def test_warn_with_empty_findings_blocks_agent(self) -> None:
        written = self._run(
            '{"result": "MALWARE_REVIEW_VERDICT: benign\\n\\n**Verdict: benign**"}',
            '{"result": "**Verdict: benign**"}',
            report={
                "status": "warn",
                "scan_conclusive": True,
                "verdict_token_in_tree": False,
                "findings": {"unicode": [], "confusable": [], "ioc": [], "heuristic": []},
            },
        )
        self.assertIn("**Verdict: malicious**", written["result"])
        self.assertNotIn("**Verdict: benign**", written["result"])
        self.assertNotIn("needs human review", written["result"])
        self.assertIs(written["complete"], True)

    def test_buried_malicious_line_is_not_published_as_benign(self) -> None:
        written = self._run(
            '{"result": "Looks fine.\\nMALWARE_REVIEW_VERDICT: malicious\\n"}',
            '{"result": "COMPATIBILITY_RECOMMENDATION: Merge\\n\\nShip it.\\n"}',
        )
        self.assertIn("**Verdict: malicious**", written["result"])
        self.assertNotIn("**Verdict: benign**", written["result"])
        self.assertNotIn("**Merge**", written["result"])
        self.assertIn("Compatibility recommendation withheld", written["result"])

    def test_bundle_generic_hits_keep_agent_verdict_and_merge_call(self) -> None:
        hits = [
            {
                "kind": "shell_process_spawn",
                "file": "lib/entry-points.js",
                "line": str(index),
                "match": "child_process",
            }
            for index in range(1, 21)
        ]
        written = self._run(
            '{"result": "MALWARE_REVIEW_VERDICT: benign\\n\\nCompiled action bundle only.\\n"}',
            '{"result": "COMPATIBILITY_RECOMMENDATION: Merge\\n\\nExisting call sites still typecheck.\\n"}',
            report={
                "status": "warn",
                "scan_conclusive": True,
                "verdict_token_in_tree": False,
                "action_entry_points": ["lib/entry-points.js"],
                "findings": {"unicode": [], "confusable": [], "ioc": [], "heuristic": hits},
            },
        )
        self.assertIn("**Verdict: benign**", written["result"])
        self.assertIn("**Merge**", written["result"])
        self.assertIn("Existing call sites still typecheck.", written["result"])
        self.assertNotIn("needs human review", written["result"])
        self.assertIs(written["complete"], True)

    def test_ioc_hit_stays_malicious_when_agent_says_benign(self) -> None:
        written = self._run(
            '{"result": "MALWARE_REVIEW_VERDICT: benign\\n\\nLooks fine.\\n"}',
            '{"result": "COMPATIBILITY_RECOMMENDATION: Merge\\n\\nAPI unchanged.\\n"}',
            report={
                "status": "warn",
                "scan_conclusive": True,
                "verdict_token_in_tree": False,
                "findings": {
                    "ioc": [
                        {
                            "kind": "ioc_match",
                            "file": "pkg/index.js",
                            "line": "4",
                            "match": "known-bad.example",
                        }
                    ],
                    "unicode": [],
                    "confusable": [],
                    "heuristic": [],
                },
            },
        )
        self.assertIn("**Verdict: malicious**", written["result"])
        self.assertIn("`pkg/index.js:4`", written["result"])
        self.assertNotIn("**Verdict: benign**", written["result"])
        self.assertNotIn("Looks fine.", written["result"])
        self.assertNotIn("**Merge**", written["result"])
        self.assertNotIn("API unchanged.", written["result"])
        self.assertIn("Compatibility recommendation withheld", written["result"])
        self.assertNotIn("needs human review", written["result"])

    def test_unicode_trick_stays_blocking_when_agent_says_benign(self) -> None:
        written = self._run(
            '{"result": "MALWARE_REVIEW_VERDICT: benign\\n\\nIgnore the controls.\\n"}',
            '{"result": "COMPATIBILITY_RECOMMENDATION: Don\'t merge\\n\\nBehavior changed.\\n"}',
            report={
                "status": "warn",
                "scan_conclusive": True,
                "verdict_token_in_tree": False,
                "findings": {
                    "ioc": [],
                    "unicode": [
                        {
                            "kind": "unicode",
                            "file": "pkg/index.js",
                            "line": "9",
                            "match": "bidi-override",
                        }
                    ],
                    "confusable": [],
                    "heuristic": [],
                },
            },
        )
        self.assertIn("**Verdict: suspicious**", written["result"])
        self.assertIn("`pkg/index.js:9`", written["result"])
        self.assertIn("bidi-override", written["result"])
        self.assertNotIn("**Verdict: benign**", written["result"])
        self.assertNotIn("Ignore the controls.", written["result"])
        self.assertIn("**Don't merge**", written["result"])
        self.assertIn("Behavior changed.", written["result"])
        self.assertNotIn("needs human review", written["result"])

    def test_scanner_that_did_not_run_states_that_and_still_calls_compatibility(self) -> None:
        written = self._run(
            '{"result": "MALWARE_REVIEW_VERDICT: benign\\n\\nNothing to see.\\n"}',
            '{"result": "COMPATIBILITY_RECOMMENDATION: Merge\\n\\nCall sites are unchanged.\\n"}',
            report={
                "status": "not_scanned",
                "scan_conclusive": False,
                "verdict_token_in_tree": False,
                "not_scanned_reason": "scanner_tools_missing",
                "findings": {"unicode": [], "confusable": [], "ioc": [], "heuristic": []},
            },
        )
        self.assertIn("**Scan could not run.**", written["result"])
        self.assertIn("scanner_tools_missing", written["result"])
        self.assertNotIn("**Verdict: benign**", written["result"])
        self.assertNotIn("Nothing to see.", written["result"])
        self.assertNotIn("needs human review", written["result"])
        self.assertIn("**Merge**", written["result"])
        self.assertIn("Call sites are unchanged.", written["result"])

    def test_agent_cannot_clear_unicode_by_escalating_only(self) -> None:
        written = self._run(
            '{"result": "MALWARE_REVIEW_VERDICT: malicious\\n\\nHidden payload.\\n"}',
            '{"result": "COMPATIBILITY_RECOMMENDATION: Merge\\n\\nUnrelated.\\n"}',
            report={
                "status": "warn",
                "scan_conclusive": True,
                "verdict_token_in_tree": False,
                "findings": {
                    "ioc": [],
                    "unicode": [
                        {"kind": "unicode", "file": "pkg/index.js", "line": 3, "match": "zero-width"}
                    ],
                    "confusable": [],
                    "heuristic": [],
                },
            },
        )
        self.assertIn("**Verdict: malicious**", written["result"])
        self.assertIn("`pkg/index.js:3`", written["result"])
        self.assertNotIn("**Merge**", written["result"])
        self.assertIn("Compatibility recommendation withheld", written["result"])

    def test_malformed_unicode_list_is_blocking(self) -> None:
        written = self._run(
            '{"result": "MALWARE_REVIEW_VERDICT: benign\\n\\nClear.\\n"}',
            '{"result": "COMPATIBILITY_RECOMMENDATION: Merge\\n\\nFine.\\n"}',
            report={
                "status": "clean",
                "scan_conclusive": True,
                "verdict_token_in_tree": False,
                "findings": {"ioc": [], "unicode": "present", "confusable": [], "heuristic": []},
            },
        )
        self.assertIn("**Verdict: malicious**", written["result"])
        self.assertNotIn("**Verdict: benign**", written["result"])
        self.assertNotIn("**Merge**", written["result"])

    def test_action_entry_point_hit_is_context_and_other_paths_are_not(self) -> None:
        finding = {
            "kind": "minified_payload_indicator",
            "file": "src/main.js",
            "line": "2",
            "match": "long-line",
        }
        report = {
            "status": "warn",
            "scan_conclusive": True,
            "verdict_token_in_tree": False,
            "findings": {"ioc": [], "unicode": [], "confusable": [], "heuristic": [finding]},
        }
        benign = '{"result": "MALWARE_REVIEW_VERDICT: benign\\n\\nEntry point only.\\n"}'
        compat = '{"result": "COMPATIBILITY_RECOMMENDATION: Don\'t merge\\n\\nNeeds a changelog.\\n"}'
        blocked = self._run(benign, compat, report=report)
        self.assertIn("**Verdict: suspicious**", blocked["result"])
        self.assertIn("`src/main.js:2`", blocked["result"])
        self.assertNotIn("Entry point only.", blocked["result"])
        self.assertIn("**Don't merge**", blocked["result"])
        self.assertIn("Needs a changelog.", blocked["result"])
        cleared = self._run(
            benign,
            compat,
            report={**report, "action_entry_points": ["src/main.js"]},
        )
        self.assertIn("**Verdict: benign**", cleared["result"])
        self.assertIn("Entry point only.", cleared["result"])
        self.assertIn("**Don't merge**", cleared["result"])


if __name__ == "__main__":
    unittest.main()
