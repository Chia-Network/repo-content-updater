"""Bugbot 3c948013: companion bootstrap without pre-primed sys.modules."""

from __future__ import annotations

import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent

_BUNDLE = (
    "script_dir_isolated_load.py",
    "companion_isolated_exec.py",
    "trusted_formatter_loader_bootstrap.py",
    "trusted_formatter_loader_cold_start.py",
    "trusted_formatter_loader.py",
    "malware_verdict_formatter.py",
    "malware_verdict_patterns.py",
    "malware_verdict_policy_types.py",
    "malware_verdict_policy_select.py",
    "malware_verdict_policy_strip.py",
    "malware_verdict_policy_analysis.py",
    "malware_verdict_policy.py",
    "dependency_cursor_review_combine_outputs.py",
)


class CompanionColdStartTest(unittest.TestCase):
    def test_3c948013_prime_formatter_without_preimported_companion(self) -> None:
        purge = (
            "companion_isolated_exec",
            "script_dir_isolated_load",
            "trusted_formatter_loader_bootstrap",
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
                    out = fn("Verdict: benign\n\nOK")
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
            proc = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(scripts / "dependency_cursor_review_combine_outputs.py"),
                ],
                cwd=root,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)


if __name__ == "__main__":
    unittest.main()
