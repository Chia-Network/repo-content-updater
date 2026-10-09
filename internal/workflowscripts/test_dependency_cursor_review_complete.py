"""complete is true only when both Cursor outputs are real analyses."""

from __future__ import annotations

import json
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
    def _run(self, malware: str | None, compatibility: str | None) -> dict:
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
            proc = subprocess.run(
                [sys.executable, "-I", str(_COMBINE)],
                cwd=root,
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
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts = root / ".github" / "scripts"
            scripts.mkdir(parents=True)
            for name in _BUNDLE_STEMS:
                shutil.copy2(_SCRIPTS / name, scripts / name)
            (root / "malware_scan_report.json").write_text(
                json.dumps(
                    {
                        "status": "not_scanned",
                        "scan_conclusive": False,
                        "verdict_token_in_tree": False,
                    }
                ),
                encoding="utf-8",
            )
            (root / "cursor_output_malware.json").write_text(
                '{"result": "MALWARE_REVIEW_VERDICT: benign\\n\\nNo IOCs."}',
                encoding="utf-8",
            )
            (root / "cursor_output_compatibility.json").write_text(
                '{"result": "compat ok"}',
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, "-I", str(_COMBINE)],
                cwd=root,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
            written = json.loads((root / "cursor_output.json").read_text(encoding="utf-8"))
            self.assertIn("**Verdict: inconclusive (needs human review)**", written["result"])
            self.assertNotIn("**Verdict: benign**", written["result"])


if __name__ == "__main__":
    unittest.main()
