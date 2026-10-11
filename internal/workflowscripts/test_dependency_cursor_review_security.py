"""Security regression tests for dependency-cursor-review workflow companions."""

from __future__ import annotations

import json
import os
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
from dependency_cursor_review_combine_outputs import trusted_tree_manifest  # noqa: E402

_BUNDLE_STEMS = (
    *_runtime.FORMATTER_RUNTIME_FILENAMES,
    *_runtime.DCR_COMBINE_EXTRA_FILENAMES,
)
_BENIGN_AGENT = '{"result":"MALWARE_REVIEW_VERDICT: benign\\n\\nNo IOCs."}'
_COMPAT_AGENT = '{"result":"compat ok"}'
_INCONCLUSIVE_REPORT = {
    "status": "not_scanned",
    "scan_conclusive": False,
    "verdict_token_in_tree": False,
}
_CONCLUSIVE_REPORT = {
    "status": "clean",
    "scan_conclusive": True,
    "verdict_token_in_tree": False,
}
_HASH_PIPELINE = (
    'find "$root" -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum'
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
            (root / "malware_scan_report.json").write_text(
                '{"status":"clean","scan_conclusive":true,"verdict_token_in_tree":false}',
                encoding="utf-8",
            )
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

    def test_trusted_tree_manifest_matches_workflow_sha256sum(self) -> None:
        workflow = _WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            'find "$trusted_root" -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum',
            workflow,
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "trusted-dcr-scripts"
            nested = root / ".github" / "scripts"
            nested.mkdir(parents=True)
            (nested / "b file.py").write_text("x\n", encoding="utf-8")
            (root / "caf\u00e9.py").write_text("u\n", encoding="utf-8")
            (root / "malware_scan_report.json").write_text("{}\n", encoding="utf-8")
            (root / "link.py").symlink_to(nested / "b file.py")
            self.assertEqual(
                trusted_tree_manifest(root),
                _bash_trusted_manifest(root),
            )

    def test_frozen_inconclusive_report_ignores_workspace_fake(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, workspace = _frozen_layout(Path(tmp), _INCONCLUSIVE_REPORT)
            proc = _run_frozen_combine(root, workspace, _bash_trusted_manifest(root))
            self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
            written = json.loads((workspace / "cursor_output.json").read_text(encoding="utf-8"))
            self.assertIn("**Verdict: inconclusive (needs human review)**", written["result"])
            self.assertNotIn("**Verdict: benign**", written["result"])

    def test_frozen_conclusive_report_publishes_benign(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, workspace = _frozen_layout(Path(tmp), _CONCLUSIVE_REPORT)
            proc = _run_frozen_combine(root, workspace, _bash_trusted_manifest(root))
            self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
            written = json.loads((workspace / "cursor_output.json").read_text(encoding="utf-8"))
            self.assertIn("**Verdict: benign**", written["result"])

    def test_hash_env_outside_trusted_checkout_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "cursor_output_malware.json").write_text(_BENIGN_AGENT, encoding="utf-8")
            (workspace / "cursor_output_compatibility.json").write_text(
                _COMPAT_AGENT, encoding="utf-8"
            )
            (workspace / "malware_scan_report.json").write_text(
                json.dumps(_CONCLUSIVE_REPORT) + "\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["TRUSTED_DCR_SCRIPTS_SHA256"] = "not-the-trusted-tree"
            proc = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(_SCRIPTS / "dependency_cursor_review_combine_outputs.py"),
                ],
                cwd=workspace,
                env=env,
                capture_output=True,
                text=True,
            )
            self._assert_combine_failed(proc, workspace)
            self.assertIn("checkout is missing", proc.stderr)

    def test_missing_freeze_hash_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, workspace = _frozen_layout(Path(tmp), _INCONCLUSIVE_REPORT)
            proc = _run_frozen_combine(root, workspace, None)
            self._assert_combine_failed(proc, workspace)
            self.assertIn("hash missing", proc.stderr)

    def test_report_missing_from_frozen_tree_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, workspace = _frozen_layout(Path(tmp), None)
            proc = _run_frozen_combine(root, workspace, _bash_trusted_manifest(root))
            self._assert_combine_failed(proc, workspace)
            self.assertIn("missing from trusted checkout", proc.stderr)

    def test_tampered_scan_report_fails_closed(self) -> None:
        cases = (
            ("flip scan_conclusive", _flip_scan_conclusive),
            ("delete report", _delete_report),
            ("swap fake report", _swap_fake_report),
        )
        for name, tamper in cases:
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as tmp:
                    root, workspace = _frozen_layout(Path(tmp), _INCONCLUSIVE_REPORT)
                    manifest = _bash_trusted_manifest(root)
                    tamper(root / "malware_scan_report.json")
                    proc = _run_frozen_combine(root, workspace, manifest)
                    self._assert_combine_failed(proc, workspace)
                    self.assertIn("changed before combine", proc.stderr)

    def _assert_combine_failed(
        self,
        proc: subprocess.CompletedProcess[str],
        workspace: Path,
    ) -> None:
        self.assertNotEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
        self.assertFalse((workspace / "cursor_output.json").exists())


def _bash_trusted_manifest(root: Path) -> str:
    proc = subprocess.run(
        [
            "bash",
            "-c",
            'root="$(cd "$1" && pwd -P)" || exit 1\n' + _HASH_PIPELINE,
            "hash_trusted_scripts",
            str(root),
        ],
        check=True,
        capture_output=True,
    )
    return proc.stdout.decode().rstrip("\n")


def _frozen_layout(base: Path, report: dict | None) -> tuple[Path, Path]:
    root = base / "trusted-dcr-scripts"
    scripts = root / ".github" / "scripts"
    scripts.mkdir(parents=True)
    for name in _BUNDLE_STEMS:
        shutil.copy2(_SCRIPTS / name, scripts / name)
    if report is not None:
        (root / "malware_scan_report.json").write_text(
            json.dumps(report) + "\n",
            encoding="utf-8",
        )
    workspace = base / "workspace"
    workspace.mkdir()
    (workspace / "cursor_output_malware.json").write_text(_BENIGN_AGENT, encoding="utf-8")
    (workspace / "cursor_output_compatibility.json").write_text(_COMPAT_AGENT, encoding="utf-8")
    (workspace / "malware_scan_report.json").write_text(
        json.dumps(_CONCLUSIVE_REPORT) + "\n",
        encoding="utf-8",
    )
    return root, workspace


def _run_frozen_combine(
    root: Path,
    workspace: Path,
    manifest: str | None,
) -> subprocess.CompletedProcess[str]:
    script = root / ".github" / "scripts" / "dependency_cursor_review_combine_outputs.py"
    env = os.environ.copy()
    env.pop("TRUSTED_DCR_SCRIPTS_SHA256", None)
    if manifest is not None:
        env["TRUSTED_DCR_SCRIPTS_SHA256"] = manifest
    return subprocess.run(
        [sys.executable, "-I", str(script)],
        cwd=workspace,
        env=env,
        capture_output=True,
        text=True,
    )


def _flip_scan_conclusive(report_path: Path) -> None:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["scan_conclusive"] = True
    report_path.write_text(json.dumps(report) + "\n", encoding="utf-8")


def _delete_report(report_path: Path) -> None:
    report_path.unlink()


def _swap_fake_report(report_path: Path) -> None:
    report_path.write_text(
        json.dumps(_CONCLUSIVE_REPORT) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    unittest.main()
