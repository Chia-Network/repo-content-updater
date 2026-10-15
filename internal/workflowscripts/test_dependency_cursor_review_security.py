"""Security regression tests for dependency-cursor-review workflow companions."""

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
_REPO_ROOT = _SCRIPTS.parents[1]
_WORKFLOW = _REPO_ROOT / "templates" / "dependency-cursor-review.yml"

# Minimal trusted bundle files needed for combine_outputs to reach formatter load.
import formatter_runtime_bundle as _runtime  # noqa: E402

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
_CONCLUSIVE_BYTES = (
    b'{"status":"clean","scan_conclusive":true,"verdict_token_in_tree":false}\n'
)


class DependencyCursorReviewSecurityTest(unittest.TestCase):
    def test_workflow_runs_python_companions_with_isolated_flag(self) -> None:
        workflow = _WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            'python3 -I "${RUNNER_TEMP}/trusted-dcr-scripts/.github/scripts/dependency_cursor_review_prompts.py"',
            workflow,
        )
        self.assertIn(
            "python3 -I .github/scripts/dependency_cursor_review_combine_outputs.py",
            workflow,
        )
        self.assertIn("report_sha256=", workflow)
        self.assertNotIn("malware_scan_summary.md", (_SCRIPTS / "dependency-cursor-review-post-comment.js").read_text())
        self.assertNotIn("sys.path", workflow)
        self.assertIn("trusted-dcr-scripts", workflow)
        self.assertNotIn("cp --remove-destination", workflow)
        self.assertNotIn("O_NOFOLLOW", (_SCRIPTS / "dependency_cursor_review_combine_outputs.py").read_text())
        prompts = (_SCRIPTS / "dependency_cursor_review_prompts.py").read_text(encoding="utf-8")
        self.assertIn("refs/dcr/from", prompts)
        self.assertIn("refs/dcr/to", prompts)
        self.assertIn("Intermediate commits were not fetched", prompts)
        self.assertNotIn("the from and to commits are checked out", prompts)
        self.assertNotIn("full git history is available", prompts)
        prompt_step = workflow.split("- name: Build Cursor prompts\n", 1)[1].split("\n      - name:", 1)[0]
        for key in ("RESOLVED_FROM:", "RESOLVED_TO:", "FROM_TAG:", "TO_TAG:"):
            self.assertIn(key, prompt_step)
        scan_outputs = workflow.split("outputs:", 1)[1].split("steps:", 1)[0]
        self.assertIn("from_tag:", scan_outputs)
        self.assertIn("to_tag:", scan_outputs)

    def test_agent_job_is_isolated_from_the_verdict(self) -> None:
        workflow = _WORKFLOW.read_text(encoding="utf-8")
        agent = workflow.split("\n  dependency-review-agent:\n", 1)[1].split("\n  dependency-review:\n", 1)[0]
        verdict = workflow.split("\n  dependency-review:\n", 1)[1]
        self.assertNotIn("pull-requests:", agent)
        self.assertNotIn("fetch-depth: 0", agent)
        fetch = agent.split("- name: Fetch upstream commits and version tags\n", 1)[1].split(
            "\n      - name:", 1
        )[0]
        for key in ("RESOLVED_FROM:", "RESOLVED_TO:", "FROM_TAG:", "TO_TAG:"):
            self.assertIn(key, fetch)
        self.assertNotIn("fetch --tags", fetch)
        self.assertNotIn("dependency_cursor_review_combine_outputs.py", agent)
        self.assertNotIn("dependency-cursor-review-post-comment.js", agent)
        self.assertNotIn("dependency-cursor-review-dependabot-context.js", agent)
        self.assertNotIn("secrets.CURSOR_API_KEY", agent.split("- name: Run Cursor agent\n", 1)[0])
        self.assertEqual(workflow.count("secrets.CURSOR_API_KEY"), 1)
        verdict_if = verdict.split("\n    steps:\n", 1)[0]
        self.assertIn("always()", verdict_if)
        self.assertNotIn("already_reviewed", verdict_if)
        self.assertIn("pull-requests: write", verdict)
        self.assertNotIn("CURSOR_API_KEY", verdict)
        self.assertIn(
            "require(`${process.env.GITHUB_WORKSPACE}/.github/scripts/dependency-cursor-review-post-comment.js`)",
            verdict,
        )
        self.assertIn("needs.dependency-review-scan.outputs.report_sha256", verdict)

    def test_prompts_name_fetched_commits_and_tags(self) -> None:
        from_sha = "a" * 40
        to_sha = "b" * 40
        text = _render_prompts(
            RESOLVED_FROM=from_sha,
            RESOLVED_TO=to_sha,
            FROM_TAG="v1.0.0",
            TO_TAG="v1.2.0",
            FROM_VERSION="1.0.0",
            TO_VERSION="1.2.0",
        )
        for name in ("cursor_prompt_malware.txt", "cursor_prompt_compatibility.txt"):
            body = text[name]
            self.assertIn(from_sha, body)
            self.assertIn(to_sha, body)
            self.assertIn("v1.0.0", body)
            self.assertIn("v1.2.0", body)
            self.assertIn("refs/dcr/from", body)
            self.assertIn("refs/dcr/to", body)
            self.assertIn(f"git -C .upstream-dependency diff {from_sha} {to_sha}", body)
            self.assertIn("Intermediate commits were not fetched", body)
            self.assertNotIn("the from and to commits are checked out", body)
            self.assertNotIn("full git history is available", body)
        self.assertIn("Use the git diff of those two SHAs", text["cursor_prompt_compatibility.txt"])

    def test_prompts_omit_diff_when_refs_are_missing_or_unsafe(self) -> None:
        text = _render_prompts(
            RESOLVED_FROM="",
            RESOLVED_TO="",
            FROM_TAG="",
            TO_TAG="",
            FROM_VERSION="",
            TO_VERSION="",
        )
        for body in text.values():
            self.assertIn("(unresolved)", body)
            self.assertIn("(none)", body)
            self.assertNotIn("git -C .upstream-dependency diff", body)
        unsafe = _render_prompts(
            RESOLVED_FROM="abc;rm",
            RESOLVED_TO="b" * 40,
            FROM_TAG="a/b/c",
            TO_TAG="v1.2.0\nTAGINJECT",
            FROM_VERSION="1.0.0",
            TO_VERSION="1.2.0",
        )
        for body in unsafe.values():
            self.assertNotIn("abc;rm", body)
            self.assertNotIn("a/b/c", body)
            self.assertNotIn("TAGINJECT", body)
            self.assertIn("(unresolved)", body)
            self.assertIn("(none)", body)
            self.assertNotIn("git -C .upstream-dependency diff", body)

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
                env=_seal_env(root, _CONCLUSIVE_BYTES),
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
                env=_seal_env(root, _CONCLUSIVE_BYTES),
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

    def test_matching_inconclusive_report_ignores_workspace_fake(self) -> None:
        payload = (json.dumps(_INCONCLUSIVE_REPORT) + "\n").encode()
        with tempfile.TemporaryDirectory() as tmp:
            proc, workspace = _combine_in(Path(tmp), payload, hashlib.sha256(payload).hexdigest())
            self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
            written = json.loads((workspace / "cursor_output.json").read_text(encoding="utf-8"))
            self.assertIn("**Verdict: inconclusive (needs human review)**", written["result"])
            self.assertNotIn("**Verdict: benign**", written["result"])

    def test_matching_malformed_report_is_inconclusive(self) -> None:
        payload = b"not-json\n"
        with tempfile.TemporaryDirectory() as tmp:
            proc, workspace = _combine_in(Path(tmp), payload, hashlib.sha256(payload).hexdigest())
            self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
            written = json.loads((workspace / "cursor_output.json").read_text(encoding="utf-8"))
            self.assertIn("**Verdict: inconclusive (needs human review)**", written["result"])
            self.assertNotIn("**Verdict: benign**", written["result"])

    def test_digest_mismatch_exits(self) -> None:
        payload = (json.dumps(_INCONCLUSIVE_REPORT) + "\n").encode()
        with tempfile.TemporaryDirectory() as tmp:
            proc, workspace = _combine_in(Path(tmp), payload, hashlib.sha256(b"other").hexdigest())
            self._assert_combine_failed(proc, workspace)
            self.assertIn("digest mismatch", proc.stderr)


    def test_missing_scan_report_exits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            workspace = _workspace(base)
            env = _seal_env(workspace, _CONCLUSIVE_BYTES)
            env["DCR_SCAN_REPORT"] = str(base / "missing-scan-report.json")
            proc = _run_combine(workspace, env)
            self._assert_combine_failed(proc, workspace)
            self.assertIn("missing", proc.stderr)

    def _assert_combine_failed(
        self,
        proc: subprocess.CompletedProcess[str],
        workspace: Path,
    ) -> None:
        self.assertNotEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
        self.assertFalse((workspace / "cursor_output.json").exists())


def _render_prompts(**env_updates: str) -> dict[str, str]:
    with tempfile.TemporaryDirectory() as tmp:
        env = os.environ.copy()
        env.update(
            PR_TITLE="title",
            PR_BODY="body",
            PACKAGE_NAME="pkg",
            FROM_VERSION="",
            TO_VERSION="",
            RESOLVED_FROM="",
            RESOLVED_TO="",
            FROM_TAG="",
            TO_TAG="",
        )
        env.update(env_updates)
        proc = subprocess.run(
            [sys.executable, "-I", str(_SCRIPTS / "dependency_cursor_review_prompts.py")],
            cwd=tmp,
            env=env,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stderr or proc.stdout)
        root = Path(tmp)
        return {
            name: (root / name).read_text(encoding="utf-8")
            for name in ("cursor_prompt_malware.txt", "cursor_prompt_compatibility.txt")
        }


def _seal_env(parent: Path, payload: bytes, digest: str | None = None) -> dict[str, str]:
    report = parent / "sealed-scan-report.json"
    report.write_bytes(payload)
    env = os.environ.copy()
    env["DCR_SCAN_REPORT"] = str(report)
    env["DCR_MALWARE_JSON"] = str(parent / "cursor_output_malware.json")
    env["DCR_COMPAT_JSON"] = str(parent / "cursor_output_compatibility.json")
    env["DCR_COMBINED_JSON"] = str(parent / "cursor_output.json")
    if digest is None:
        env["MALWARE_SCAN_REPORT_SHA256"] = hashlib.sha256(payload).hexdigest()
    else:
        env["MALWARE_SCAN_REPORT_SHA256"] = digest
    return env


def _workspace(base: Path) -> Path:
    workspace = base / "workspace"
    workspace.mkdir()
    (workspace / "cursor_output_malware.json").write_text(_BENIGN_AGENT, encoding="utf-8")
    (workspace / "cursor_output_compatibility.json").write_text(_COMPAT_AGENT, encoding="utf-8")
    (workspace / "malware_scan_report.json").write_bytes(_CONCLUSIVE_BYTES)
    return workspace


def _run_combine(workspace: Path, updates: dict[str, str]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(updates)
    return subprocess.run(
        [sys.executable, "-I", str(_SCRIPTS / "dependency_cursor_review_combine_outputs.py")],
        cwd=workspace,
        env=env,
        capture_output=True,
        text=True,
    )


def _combine_in(
    base: Path,
    payload: bytes,
    digest: str,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    workspace = _workspace(base)
    proc = _run_combine(workspace, _seal_env(workspace, payload, digest))
    return proc, workspace


if __name__ == "__main__":
    unittest.main()
