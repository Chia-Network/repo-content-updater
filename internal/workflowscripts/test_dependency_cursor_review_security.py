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
_FROZEN_NAME = "frozen-malware-scan-report.json"


class DependencyCursorReviewSecurityTest(unittest.TestCase):
    def test_workflow_runs_python_companions_with_isolated_flag(self) -> None:
        workflow = _WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            '/usr/bin/python3 -I "${RUNNER_TEMP}/trusted-dcr-scripts/.github/scripts/dependency_cursor_review_prompts.py"',
            workflow,
        )
        self.assertIn("/usr/bin/python3 -I -c", workflow)
        self.assertIn('exec(compile(data, path, "exec")', workflow)
        self.assertNotIn(
            '/usr/bin/python3 -I "${RUNNER_TEMP}/trusted-dcr-scripts/.github/scripts/dependency_cursor_review_combine_outputs.py"',
            workflow,
        )
        self.assertIn("cp --remove-destination", workflow)
        self.assertIn("/usr/bin/sha256sum", workflow)
        self.assertIn("report_sha256=", workflow)
        self.assertNotIn("malware_scan_summary.md", (_SCRIPTS / "dependency-cursor-review-post-comment.js").read_text())
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

    def test_digest_mismatch_exits(self) -> None:
        payload = (json.dumps(_INCONCLUSIVE_REPORT) + "\n").encode()
        with tempfile.TemporaryDirectory() as tmp:
            proc, workspace = _combine_in(Path(tmp), payload, hashlib.sha256(b"other").hexdigest())
            self._assert_combine_failed(proc, workspace)
            self.assertIn("digest mismatch", proc.stderr)

    def test_empty_digest_exits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc, workspace = _combine_in(Path(tmp), _CONCLUSIVE_BYTES, "")
            self._assert_combine_failed(proc, workspace)
            self.assertIn("digest is missing", proc.stderr)

    def test_frozen_symlink_is_rejected(self) -> None:
        payload = _CONCLUSIVE_BYTES
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            real = base / "real.json"
            real.write_bytes(payload)
            runner = base / "runner-temp"
            runner.mkdir()
            frozen = runner / _FROZEN_NAME
            frozen.symlink_to(real)
            workspace = _workspace(base)
            proc = _run_combine(
                workspace,
                {
                    "RUNNER_TEMP": str(runner),
                    "MALWARE_SCAN_REPORT_SHA256": hashlib.sha256(payload).hexdigest(),
                },
            )
            self._assert_combine_failed(proc, workspace)
            self.assertIn("symlink", proc.stderr)

    def test_cp_remove_destination_does_not_follow_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "malware_scan_report.json"
            source.write_bytes(_CONCLUSIVE_BYTES)
            secret = base / "secret.txt"
            secret.write_text("original-secret\n", encoding="utf-8")
            dest = base / _FROZEN_NAME
            dest.symlink_to(secret)
            subprocess.run(
                ["cp", "--remove-destination", str(source), str(dest)],
                check=True,
            )
            self.assertFalse(dest.is_symlink())
            self.assertEqual(dest.read_bytes(), _CONCLUSIVE_BYTES)
            self.assertEqual(secret.read_text(encoding="utf-8"), "original-secret\n")

    def test_malformed_json_with_matching_digest_is_inconclusive(self) -> None:
        payload = b"{not-json"
        with tempfile.TemporaryDirectory() as tmp:
            proc, workspace = _combine_in(Path(tmp), payload, hashlib.sha256(payload).hexdigest())
            self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
            written = json.loads((workspace / "cursor_output.json").read_text(encoding="utf-8"))
            self.assertIn("**Verdict: inconclusive (needs human review)**", written["result"])
            self.assertNotIn("**Verdict: benign**", written["result"])

    def test_missing_frozen_report_exits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            runner = base / "runner-temp"
            runner.mkdir()
            workspace = _workspace(base)
            proc = _run_combine(
                workspace,
                {
                    "RUNNER_TEMP": str(runner),
                    "MALWARE_SCAN_REPORT_SHA256": hashlib.sha256(_CONCLUSIVE_BYTES).hexdigest(),
                },
            )
            self._assert_combine_failed(proc, workspace)
            self.assertIn("missing", proc.stderr)

    def test_replaced_post_comment_helper_is_refused(self) -> None:
        workflow = _WORKFLOW.read_text(encoding="utf-8")
        script = _script_block(workflow, "Post or update PR comment")
        self.assertIn("helperModule._compile", script)
        self.assertNotIn("require(helperPath)", script)
        self.assertNotIn(
            "require(`${process.env.RUNNER_TEMP}/trusted-dcr-helper/dependency-cursor-review-post-comment.js`)",
            script,
        )
        with tempfile.TemporaryDirectory() as tmp:
            runner = Path(tmp)
            helper_dir = runner / "trusted-dcr-helper"
            helper_dir.mkdir()
            for name in (
                "dependency-cursor-review-post-comment.js",
                "dependency-cursor-review-dependabot-context.js",
            ):
                shutil.copy2(_SCRIPTS / name, helper_dir / name)
            target = helper_dir / "dependency-cursor-review-post-comment.js"
            original = target.read_bytes()
            digest = hashlib.sha256(original).hexdigest()
            loaded = _run_post_script(script, runner, digest)
            self.assertEqual(loaded.returncode, 0, msg=loaded.stderr or loaded.stdout)
            self.assertIn("Posted dependency review comment", loaded.stdout)
            target.write_text(
                "module.exports = async () => { console.log('tampered-helper'); };\n",
                encoding="utf-8",
            )
            refused = _run_post_script(script, runner, digest)
            self.assertNotEqual(refused.returncode, 0, msg=refused.stdout)
            self.assertIn("digest mismatch", refused.stderr)
            self.assertNotIn("tampered-helper", refused.stdout)
            self.assertNotIn("Posted dependency review comment", refused.stdout)

    def test_combine_runs_snapshotted_bytes_after_disk_change(self) -> None:
        workflow = _WORKFLOW.read_text(encoding="utf-8")
        run = _run_block(workflow, "Run Cursor analysis")
        loop_start = run.index('combine_digest=""')
        loop_end = run.index('done <<< "$trusted_hash_snapshot"')
        loop_end += len('done <<< "$trusted_hash_snapshot"')
        loop = run[loop_start:loop_end]
        capture = 'combine_b64="$(/usr/bin/base64 -w0 "$combine_path")"'
        exec_line = next(line for line in run.splitlines() if line.startswith("printf '%s' \"$combine_b64\""))
        self.assertIn(capture, run)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            trusted = base / "trusted-dcr-scripts"
            scripts = trusted / ".github" / "scripts"
            scripts.mkdir(parents=True)
            for name in _BUNDLE_STEMS:
                shutil.copy2(_SCRIPTS / name, scripts / name)
            combine_path = scripts / "dependency_cursor_review_combine_outputs.py"
            original = combine_path.read_bytes()
            workspace = _workspace(base)
            runner = base / "runner-temp"
            runner.mkdir()
            (runner / _FROZEN_NAME).write_bytes(_CONCLUSIVE_BYTES)
            env = os.environ.copy()
            env.update(
                {
                    "RUNNER_TEMP": str(runner),
                    "MALWARE_SCAN_REPORT_SHA256": hashlib.sha256(_CONCLUSIVE_BYTES).hexdigest(),
                }
            )
            shell = "\n".join(
                [
                    "set -euo pipefail",
                    'trusted_root="$TRUSTED_ROOT"',
                    "trusted_hash_snapshot=\"$(/usr/bin/find \"$trusted_root\" -type f -print0 | LC_ALL=C /usr/bin/sort -z | /usr/bin/xargs -0 -r /usr/bin/sha256sum)\"",
                    'combine_path="$COMBINE_PATH"',
                    loop,
                    capture,
                    "printf '%s\\n' 'import sys' 'sys.stderr.write(\"TAMPERED\\n\")' 'sys.exit(9)' > \"$combine_path\"",
                    exec_line,
                ]
            )
            env["TRUSTED_ROOT"] = str(trusted)
            env["COMBINE_PATH"] = str(combine_path)
            proc = subprocess.run(
                ["bash", "-c", shell],
                cwd=workspace,
                env=env,
                capture_output=True,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr.decode() or proc.stdout.decode())
            self.assertNotIn(b"TAMPERED", proc.stderr)
            written = json.loads((workspace / "cursor_output.json").read_text(encoding="utf-8"))
            self.assertIn("Supply-Chain Malware Review", written["result"])
            self.assertNotEqual(combine_path.read_bytes(), original)

    def test_upload_check_deletes_replaced_frozen_report(self) -> None:
        workflow = _WORKFLOW.read_text(encoding="utf-8")
        run = _run_block(workflow, "Check frozen malware scan report")
        upload = workflow.split("- name: Upload malware scan artifacts\n", 1)[1].split("\n      - name:", 1)[0]
        self.assertNotIn("upstream_changed_files.txt", upload)
        with tempfile.TemporaryDirectory() as tmp:
            runner = Path(tmp)
            frozen = runner / _FROZEN_NAME
            frozen.write_bytes(b"replaced\n")
            env = os.environ.copy()
            env["RUNNER_TEMP"] = str(runner)
            env["REPORT_SHA256"] = hashlib.sha256(b"original\n").hexdigest()
            proc = subprocess.run(
                ["bash", "-c", run],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(proc.returncode, 0, msg=proc.stdout)
            self.assertFalse(frozen.exists())
            self.assertIn("digest mismatch", proc.stderr)

    def _assert_combine_failed(
        self,
        proc: subprocess.CompletedProcess[str],
        workspace: Path,
    ) -> None:
        self.assertNotEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
        self.assertFalse((workspace / "cursor_output.json").exists())


def _seal_env(parent: Path, payload: bytes, digest: str | None = None) -> dict[str, str]:
    runner = parent / "runner-temp"
    runner.mkdir(exist_ok=True)
    (runner / _FROZEN_NAME).write_bytes(payload)
    env = os.environ.copy()
    env["RUNNER_TEMP"] = str(runner)
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
    runner = base / "runner-temp"
    runner.mkdir()
    (runner / _FROZEN_NAME).write_bytes(payload)
    workspace = _workspace(base)
    proc = _run_combine(
        workspace,
        {"RUNNER_TEMP": str(runner), "MALWARE_SCAN_REPORT_SHA256": digest},
    )
    return proc, workspace


def _run_block(workflow: str, step_name: str) -> str:
    section = workflow.split(f"- name: {step_name}\n", 1)[1]
    section = section.split("\n      - name:", 1)[0]
    body = section.split("run: |\n", 1)[1]
    lines = body.splitlines()
    indents = [len(line) - len(line.lstrip(" ")) for line in lines if line.strip()]
    base = min(indents) if indents else 0
    dedented = [(line[base:] if line.startswith(" " * base) else line) for line in lines]
    return "\n".join(dedented).strip() + "\n"


def _script_block(workflow: str, step_name: str) -> str:
    section = workflow.split(f"- name: {step_name}\n", 1)[1]
    body = section.split("script: |\n", 1)[1]
    lines: list[str] = []
    for line in body.splitlines():
        if line.startswith("            "):
            lines.append(line[12:])
        elif line.strip() == "":
            lines.append("")
        else:
            break
    return "\n".join(lines).strip() + "\n"


def _run_post_script(script: str, runner_temp: Path, digest: str) -> subprocess.CompletedProcess[str]:
    wrapper = """
const core = {
  info(message) { console.log(message); },
  setFailed(message) { console.error(message); process.exitCode = 1; },
};
const github = {
  paginate: async () => [],
  rest: {
    issues: {
      listComments: async () => [],
      createComment: async () => ({}),
      updateComment: async () => ({}),
    },
  },
};
const context = { repo: { owner: 'acme', repo: 'widgets' } };
(async () => {
__SCRIPT__
})().catch((err) => {
  console.error(err && err.message ? err.message : String(err));
  process.exitCode = 1;
});
"""
    env = os.environ.copy()
    env["RUNNER_TEMP"] = str(runner_temp)
    env["POST_COMMENT_SHA256"] = digest
    env["PR_NUMBER"] = "1"
    env["REVIEW_MARKER"] = ""
    env["MALWARE_SCAN_STATUS"] = "clean"
    env["MALWARE_SCAN_CHANGED_COUNT"] = "0"
    env["MALWARE_SCAN_SUMMARY"] = "summary"
    return subprocess.run(
        ["node", "-e", wrapper.replace("__SCRIPT__", script)],
        env=env,
        capture_output=True,
        text=True,
    )


if __name__ == "__main__":
    unittest.main()
