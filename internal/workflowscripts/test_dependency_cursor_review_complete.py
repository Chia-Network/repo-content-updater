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
            runner = root / "runner-temp"
            runner.mkdir()
            (runner / "frozen-malware-scan-report.json").write_bytes(payload)
            env = os.environ.copy()
            env["RUNNER_TEMP"] = str(runner)
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

    def test_both_good(self) -> None:
        written = self._run(
            '{"result": "Verdict: benign"}',
            '{"result": "compat ok"}',
        )
        self.assertIs(written["complete"], True)

    def test_not_scanned_report_forces_inconclusive_over_benign_line(self) -> None:
        written = self._run(
            '{"result": "MALWARE_REVIEW_VERDICT: benign\\n\\nNo IOCs."}',
            '{"result": "compat ok"}',
            report={
                "status": "not_scanned",
                "scan_conclusive": False,
                "verdict_token_in_tree": False,
            },
        )
        self.assertIn("**Verdict: inconclusive (needs human review)**", written["result"])
        self.assertNotIn("**Verdict: benign**", written["result"])


if __name__ == "__main__":
    unittest.main()
