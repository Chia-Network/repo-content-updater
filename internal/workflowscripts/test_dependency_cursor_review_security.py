"""Security regression tests for dependency-cursor-review workflow companions."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPTS.parents[1]
_WORKFLOW = _REPO_ROOT / "templates" / "dependency-cursor-review.yml"

# Minimal trusted bundle files needed for combine_outputs to reach formatter load.
import formatter_runtime_bundle as _runtime  # noqa: E402

_BUNDLE_STEMS = (
    *_runtime.FORMATTER_RUNTIME_FILENAMES,
    *_runtime.DCR_COMBINE_EXTRA_FILENAMES,
)


class DependencyCursorReviewSecurityTest(unittest.TestCase):
    def test_workflow_runs_python_companions_with_isolated_flag(self) -> None:
        workflow = _WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            'python3 -I "${RUNNER_TEMP}/trusted-dcr-scripts/.github/scripts/dependency_cursor_review_prompts.py"',
            workflow,
        )
        self.assertIn(
            'python3 -I "${RUNNER_TEMP}/trusted-dcr-scripts/.github/scripts/dependency_cursor_review_combine_outputs.py"',
            workflow,
        )
        self.assertNotIn("sys.path", workflow)
        self.assertIn("trusted-dcr-scripts", workflow)

    def test_a46061b8_combine_resists_importlib_shadow_on_scripts_dir(self) -> None:
        """Scripts-dir shadow must not run when bootstrap/companion load scrubs sys.path."""
        with tempfile.TemporaryDirectory() as tmp:
            scripts = Path(tmp) / "scripts"
            scripts.mkdir()
            for name in _BUNDLE_STEMS:
                shutil.copy2(_SCRIPTS / name, scripts / name)
            (scripts / "importlib.py").write_text(
                "raise RuntimeError('untrusted importlib shadow')\n",
                encoding="utf-8",
            )
            (scripts / "cursor_output_malware.json").write_text(
                '{"result":"Verdict: benign\\n\\nOK"}', encoding="utf-8"
            )
            (scripts / "cursor_output_compatibility.json").write_text(
                '{"result":"compat ok"}', encoding="utf-8"
            )
            script_dir = str(scripts.resolve())
            sys.path.insert(0, script_dir)
            try:
                import runpy

                ns = runpy.run_path(
                    str(scripts / "trusted_formatter_loader_cold_start.py")
                )
                loader, _ = ns["resolve_loader_bundle"]((scripts,))
                self.assertTrue(
                    hasattr(loader, "find_and_load_format_malware_review_verdict")
                )
            finally:
                sys.path[:] = [p for p in sys.path if p != script_dir]

    def test_a46061b8_python_I_combine_subprocess_with_json_shadow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts = root / ".github" / "scripts"
            scripts.mkdir(parents=True)
            for name in _BUNDLE_STEMS:
                shutil.copy2(_SCRIPTS / name, scripts / name)
            (scripts / "json.py").write_text(
                "raise RuntimeError('untrusted json shadow')\n",
                encoding="utf-8",
            )
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
            self.assertEqual(
                proc.returncode,
                0,
                msg=proc.stderr or proc.stdout,
            )
            out = (root / "cursor_output.json").read_text(encoding="utf-8")
            self.assertIn("Supply-Chain Malware Review", out)

    def test_isolated_trusted_dir_ignores_pr_head_formatter(self) -> None:
        """PR-head .github/scripts must not supply the formatter when combine runs elsewhere."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pr_scripts = root / ".github" / "scripts"
            pr_scripts.mkdir(parents=True)
            package = pr_scripts / "malware_verdict_formatter"
            package.mkdir()
            (package / "__init__.py").write_text(
                "def format_malware_review_verdict(_text):\n"
                "    return '**Verdict: hijacked**'\n",
                encoding="utf-8",
            )
            (pr_scripts / "dataclasses.py").write_text(
                "raise RuntimeError('untrusted dataclasses shadow')\n",
                encoding="utf-8",
            )
            trusted = root / "trusted-scripts"
            trusted.mkdir()
            for name in _BUNDLE_STEMS:
                shutil.copy2(_SCRIPTS / name, trusted / name)
            (root / "cursor_output_malware.json").write_text(
                '{"result":"MALWARE_REVIEW_VERDICT: benign\\n\\nOK"}',
                encoding="utf-8",
            )
            (root / "cursor_output_compatibility.json").write_text(
                '{"result":"compat ok"}',
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(trusted / "dependency_cursor_review_combine_outputs.py"),
                ],
                cwd=root,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
            out = (root / "cursor_output.json").read_text(encoding="utf-8")
            self.assertIn("**Verdict: benign**", out)
            self.assertNotIn("hijacked", out)

    def test_util_register_scrubs_scripts_dir_on_first_exec(self) -> None:
        """Bootstrap util registration must not run with scripts dir on sys.path."""
        with tempfile.TemporaryDirectory() as tmp:
            scripts = Path(tmp) / "scripts"
            scripts.mkdir()
            for name in _BUNDLE_STEMS:
                shutil.copy2(_SCRIPTS / name, scripts / name)
            (scripts / "importlib.py").write_text(
                "raise RuntimeError('untrusted importlib shadow')\n",
                encoding="utf-8",
            )
            script_dir = str(scripts.resolve())
            sys.path.insert(0, script_dir)
            purge = (
                "isolated_module_exec",
                "isolated_module_exec",
                "trusted_formatter_loader",
            )
            saved = {name: sys.modules.pop(name, None) for name in purge}
            try:
                import runpy

                ns = runpy.run_path(
                    str(scripts / "trusted_formatter_loader_cold_start.py")
                )
                ns["resolve_loader_for_dir"](scripts)
            finally:
                sys.path[:] = [p for p in sys.path if p != script_dir]
                for name, module in saved.items():
                    if module is None:
                        sys.modules.pop(name, None)
                    else:
                        sys.modules[name] = module


if __name__ == "__main__":
    unittest.main()
