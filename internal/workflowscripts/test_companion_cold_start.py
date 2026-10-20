"""Bugbot 3c948013: companion bootstrap without pre-primed sys.modules."""

from __future__ import annotations

import hashlib
import os
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent

import formatter_runtime_bundle as _runtime  # noqa: E402

_BUNDLE = (
    *_runtime.FORMATTER_RUNTIME_FILENAMES,
    *_runtime.DCR_COMBINE_EXTRA_FILENAMES,
)


class CompanionColdStartTest(unittest.TestCase):
    def test_3c948013_prime_formatter_without_preimported_companion(self) -> None:
        purge = (
            "isolated_module_exec",
            "isolated_module_exec",
            "trusted_formatter_loader",
        )
        saved = {name: sys.modules.pop(name, None) for name in purge}
        try:
            with tempfile.TemporaryDirectory() as tmp:
                scripts = Path(tmp) / "scripts"
                scripts.mkdir()
                for name in _BUNDLE:
                    shutil.copy2(_SCRIPTS / name, scripts / name)
                script_dir = str(scripts.resolve())
                sys.path.insert(0, script_dir)
                try:
                    ns = runpy.run_path(
                        str(scripts / "trusted_formatter_loader_cold_start.py")
                    )
                    loader, _ = ns["resolve_loader_bundle"]((scripts,))
                    fn = loader.find_and_load_format_malware_review_verdict(scripts)
                    out = fn("MALWARE_REVIEW_VERDICT: benign\n\nOK")
                    self.assertTrue(out.startswith("**Verdict: benign**"))
                finally:
                    sys.path[:] = [p for p in sys.path if p != script_dir]
        finally:
            for name, module in saved.items():
                if module is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = module

    def test_3c948013_python_I_combine_cold_start(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts = root / ".github" / "scripts"
            scripts.mkdir(parents=True)
            for name in _BUNDLE:
                shutil.copy2(_SCRIPTS / name, scripts / name)
            (root / "cursor_output_malware.json").write_text(
                '{"result":"Verdict: benign\\n\\nOK"}', encoding="utf-8"
            )
            (root / "cursor_output_compatibility.json").write_text(
                '{"result":"compat ok"}', encoding="utf-8"
            )
            # The scan gate runs before the formatter. Pass a conclusive
            # report through the verdict job's env-path contract so this still
            # proves python -I cold start, not an early exit.
            payload = (
                b'{"status":"clean","scan_conclusive":true,'
                b'"verdict_token_in_tree":false,'
                b'"findings":{"ioc":[],"unicode":[],"confusable":[],"heuristic":[]}}\n'
            )
            report = root / "sealed-scan-report.json"
            report.write_bytes(payload)
            env = os.environ.copy()
            env["DCR_SCAN_REPORT"] = str(report)
            env["DCR_MALWARE_JSON"] = str(root / "cursor_output_malware.json")
            env["DCR_COMPAT_JSON"] = str(root / "cursor_output_compatibility.json")
            env["DCR_COMBINED_JSON"] = str(root / "cursor_output.json")
            env["MALWARE_SCAN_REPORT_SHA256"] = hashlib.sha256(payload).hexdigest()
            proc = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(scripts / "dependency_cursor_review_combine_outputs.py"),
                ],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
            written = (root / "cursor_output.json").read_text(encoding="utf-8")
            self.assertIn("Supply-Chain Malware Review", written)


if __name__ == "__main__":
    unittest.main()
