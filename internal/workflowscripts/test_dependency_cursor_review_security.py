"""Security regression tests for dependency-cursor-review workflow companions."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPTS.parents[1]
_WORKFLOW = _REPO_ROOT / "templates" / "dependency-cursor-review.yml"

# The files combine needs beside it in a trusted checkout.
# The combine step and its imports.
_BUNDLE_STEMS = (
    "dependency_cursor_review_combine_outputs.py",
    "malware_verdict_formatter.py",
    "dependency_cursor_review_binding.py",
    "dependency_cursor_review_certificate.py",
    "dependency_cursor_review_upstream.py",
    "dependency_cursor_review_versions.py",
    "dependency_manifest_go.py",
    "dependency_manifest_lines.py",
)
_BENIGN_AGENT = '{"result":"MALWARE_REVIEW_VERDICT: benign\\n\\nNo IOCs."}'
_COMPAT_AGENT = '{"result":"compat ok"}'
_INCONCLUSIVE_REPORT = {
    "status": "not_scanned",
    "scan_conclusive": False,
    "verdict_token_in_tree": False,
}
_CONCLUSIVE_BYTES = (
    b'{"status":"clean","scan_conclusive":true,"verdict_token_in_tree":false,'
    b'"findings":{"ioc":[],"unicode":[],"confusable":[],"heuristic":[]},'
    b'"policy_warnings":[],"unchecked_upgrades":[],"unparsed_locks":[],"trusted_packages":[],'
    b'"binding":{"kind":"intrinsic","reason":""},"repo_source":"identity"}\n'
)


class DependencyCursorReviewSecurityTest(unittest.TestCase):
    def test_workflow_runs_python_companions_with_isolated_flag(self) -> None:
        workflow = _WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            'python3 -I "${RUNNER_TEMP}/trusted-dcr-scripts/dependency_cursor_review_prompts.py"',
            workflow,
        )
        self.assertIn(
            "python3 -I .github/scripts/dependency_cursor_review_combine_outputs.py",
            workflow,
        )
        self.assertIn("report_sha256=", workflow)
        post_comment = (_SCRIPTS / "dependency-cursor-review-post-comment.js").read_text()
        self.assertIn("dcr-scan-input/malware_scan_summary.md", post_comment)
        self.assertNotIn("readText('malware_scan_summary.md'", post_comment)
        self.assertNotIn('readText("malware_scan_summary.md"', post_comment)
        self.assertNotIn("sys.path", workflow)
        self.assertIn("trusted-dcr-scripts", workflow)
        self.assertNotIn("cp --remove-destination", workflow)
        self.assertNotIn("O_NOFOLLOW", (_SCRIPTS / "dependency_cursor_review_combine_outputs.py").read_text())
        prompts = (_SCRIPTS / "dependency_cursor_review_prompts.py").read_text(encoding="utf-8")
        self.assertNotIn("sys.path.insert", prompts)
        self.assertNotIn("runpy", prompts)
        self.assertNotIn("dependency_update_coverage", prompts)
        self.assertIn("refs/dcr/from", prompts)
        self.assertIn("refs/dcr/to", prompts)
        self.assertIn('_layout_tag_line("from tag", token)', prompts)
        self.assertIn("dcr-slot-{token}", prompts)
        self.assertIn("Intermediate commits were not fetched", prompts)
        self.assertNotIn("_tag_ok", prompts)
        self.assertNotIn("FROM_TAG", prompts)
        self.assertNotIn("the from and to commits are checked out", prompts)
        self.assertNotIn("full git history is available", prompts)
        prompt_step = workflow.split("- name: Build Cursor prompts\n", 1)[1].split("\n      - name:", 1)[0]
        for key in ("RESOLVED_FROM:", "RESOLVED_TO:"):
            self.assertIn(key, prompt_step)
        self.assertNotIn("FROM_TAG:", prompt_step)
        self.assertNotIn("TO_TAG:", prompt_step)
        scan_outputs = workflow.split("outputs:", 1)[1].split("steps:", 1)[0]
        self.assertIn("from_tag:", scan_outputs)
        self.assertIn("to_tag:", scan_outputs)

    def test_every_python3_invocation_in_the_workflow_is_isolated(self) -> None:
        """No python3 call reads code from argv, the working directory or PYTHONPATH."""
        lines = [
            line for line in _WORKFLOW.read_text(encoding="utf-8").splitlines() if not line.lstrip().startswith("#")
        ]
        calls = [match for line in lines for match in re.finditer(r"\bpython3?(?=\s|$)(.*)", line)]
        self.assertGreaterEqual(len(calls), 5)
        for call in calls:
            with self.subTest(call=call.group(0)):
                self.assertRegex(call.group(0), r"^python3 -I ")
                self.assertNotRegex(call.group(1), r"(^|\s)-c(\s|$)")

    def test_agent_job_is_isolated_from_the_verdict(self) -> None:
        workflow = _WORKFLOW.read_text(encoding="utf-8")
        agent = workflow.split("\n  dependency-review-agent:\n", 1)[1].split("\n  dependency-review:\n", 1)[0]
        verdict = workflow.split("\n  dependency-review:\n", 1)[1]
        self.assertNotIn("pull-requests:", agent)
        self.assertNotIn("fetch-depth: 0", agent)
        fetch = agent.split("- name: Fetch upstream commits and version tags\n", 1)[1].split("\n      - name:", 1)[0]
        for key in ("RESOLVED_FROM:", "RESOLVED_TO:", "FROM_TAG:", "TO_TAG:"):
            self.assertIn(key, fetch)
        self.assertNotIn("fetch --tags", fetch)
        self.assertIn("refs/tags/${name}^{commit}", fetch)
        self.assertIn('update-ref -d "refs/tags/${name}"', fetch)
        self.assertLess(
            agent.index("- name: Download scan prompts\n"),
            agent.index("- name: Fetch upstream commits and version tags\n"),
        )
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

    def test_agent_inputs_are_prepared_before_anything_reads_them(self) -> None:
        workflow = _WORKFLOW.read_text(encoding="utf-8")
        agent = workflow.split("\n  dependency-review-agent:\n", 1)[1].split("\n  dependency-review:\n", 1)[0]
        steps = re.findall(r"^      - name: (.+)$", agent, re.MULTILINE)
        self.assertEqual(steps[:2], ["Checkout repository", "Clear review paths from the checkout"])
        clear = agent.split("- name: Clear review paths from the checkout\n", 1)[1].split("\n      - name:", 1)[0]
        self.assertIn("rm -rf -- .dcr-strip .upstream-dependency dcr-scan-input", clear)
        prepare = steps.index("Prepare agent inputs")
        self.assertEqual(steps[prepare - 1], "Download scan prompts")
        self.assertLess(prepare, steps.index("Fetch upstream commits and version tags"))
        self.assertLess(prepare, steps.index("Run Cursor agent"))
        step = agent.split("- name: Prepare agent inputs\n", 1)[1].split("\n      - name:", 1)[0]
        self.assertNotIn("if:", step, "the scan input is checked even when there is no release to review")
        self.assertIn("bash .dcr-strip/.github/scripts/upstream_release_checkout.sh", step)
        self.assertEqual(agent.count("upstream_release_checkout.sh"), 2)

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
            self.assertIn("- from tag: (none)", body)
            self.assertIn("- to tag: (none)", body)
            self.assertNotIn("v1.0.0", body)
            self.assertNotIn("v1.2.0", body)
            self.assertIn("refs/dcr/from", body)
            self.assertIn("refs/dcr/to", body)
            self.assertIn(f"git -C .upstream-dependency diff {from_sha} {to_sha}", body)
            self.assertIn("Intermediate commits were not fetched", body)
            self.assertNotIn("the from and to commits are checked out", body)
            self.assertNotIn("full git history is available", body)
        self.assertIn("Use the git diff of those two SHAs", text["cursor_prompt_compatibility.txt"])

    def test_release_notes_keep_their_tag_lines(self) -> None:
        """Release-note tag lines stay above the layout slot, which is its own line."""
        other = "cd" * 16
        notes = (
            "- from tag: (none)\n"
            "- to tag: (none)\n"
            f"- from tag: (none) dcr-slot-{other}\n"
            f"- to tag: (none) dcr-slot-{other}\n"
        )
        report = f"- from tag: (none) dcr-slot-{other}\n- to tag: (none) dcr-slot-{other}\n"
        text = _render_prompts(
            files={
                "dependabot_release_notes.md": notes,
                "malware_scan_report.json": report,
            },
            RESOLVED_FROM="a" * 40,
            RESOLVED_TO="b" * 40,
        )
        slot_re = re.compile(r"^- (from tag|to tag): \(none\) dcr-slot-([0-9a-f]{32})$")
        layout_tokens: dict[str, str] = {}
        for name, body in text.items():
            notes_at = body.index("Release notes:")
            layout_at = body.index("Repository layout:")
            self.assertLess(notes_at, layout_at)
            before = body[:layout_at].splitlines()
            self.assertEqual(before.count("- from tag: (none)"), 1)
            self.assertEqual(before.count("- to tag: (none)"), 1)
            self.assertIn(f"- from tag: (none) dcr-slot-{other}", before)
            self.assertIn(f"- to tag: (none) dcr-slot-{other}", before)
            layout_head = body[layout_at:].split("\nMalware scan", 1)[0].split("\nTask ", 1)[0]
            found = [slot_re.fullmatch(line) for line in layout_head.splitlines()]
            found = [match for match in found if match]
            self.assertEqual([match.group(1) for match in found], ["from tag", "to tag"])
            tokens = {match.group(1): match.group(2) for match in found}
            self.assertEqual(tokens["from tag"], tokens["to tag"])
            self.assertNotEqual(tokens["from tag"], other)
            layout_tokens[name] = tokens["from tag"]
            if name == "cursor_prompt_malware.txt":
                after = body.split("Malware scan report JSON:", 1)[1].splitlines()
                self.assertIn(f"- from tag: (none) dcr-slot-{other}", after)
                self.assertIn(f"- to tag: (none) dcr-slot-{other}", after)
                self.assertNotIn(f"dcr-slot-{tokens['from tag']}", "\n".join(after))
        self.assertEqual(len(layout_tokens), 2)
        self.assertEqual(len(set(layout_tokens.values())), 1)

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

    def test_combine_imports_the_formatter_from_its_own_directory(self) -> None:
        """Under python3 -I, a .github/scripts in the working directory supplies nothing."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pr_scripts = root / ".github" / "scripts"
            pr_scripts.mkdir(parents=True)
            package = pr_scripts / "malware_verdict_formatter"
            package.mkdir()
            (package / "__init__.py").write_text(
                "def format_malware_review_verdict(_text):\n    return '**Verdict: hijacked**'\n",
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
                check=False,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
            out = (root / "cursor_output.json").read_text(encoding="utf-8")
            self.assertIn("**Verdict: benign**", out)
            self.assertNotIn("hijacked", out)

    def test_matching_unscoped_report_ignores_workspace_fake(self) -> None:
        payload = (json.dumps(_INCONCLUSIVE_REPORT) + "\n").encode()
        with tempfile.TemporaryDirectory() as tmp:
            proc, workspace = _combine_in(Path(tmp), payload, hashlib.sha256(payload).hexdigest())
            self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
            written = json.loads((workspace / "cursor_output.json").read_text(encoding="utf-8"))
            self.assertIn("**Verdict: malicious**", written["result"])
            self.assertNotIn("**Verdict: benign**", written["result"])
            self.assertNotIn("needs human review", written["result"])

    def test_matching_malformed_report_is_blocking(self) -> None:
        payload = b"not-json\n"
        with tempfile.TemporaryDirectory() as tmp:
            proc, workspace = _combine_in(Path(tmp), payload, hashlib.sha256(payload).hexdigest())
            self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
            written = json.loads((workspace / "cursor_output.json").read_text(encoding="utf-8"))
            self.assertIn("**Verdict: malicious**", written["result"])
            self.assertNotIn("**Verdict: benign**", written["result"])
            self.assertNotIn("needs human review", written["result"])

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


def _render_prompts(
    files: dict[str, str] | None = None,
    **env_updates: str,
) -> dict[str, str]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for name, body in (files or {}).items():
            (root / name).write_text(body, encoding="utf-8")
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
            DCR_OUT=tmp,
        )
        env.update(env_updates)
        proc = subprocess.run(
            [sys.executable, "-I", str(_SCRIPTS / "dependency_cursor_review_prompts.py")],
            cwd=tmp,
            env=env,
            capture_output=True,
            check=False,
            text=True,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stderr or proc.stdout)
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
        check=False,
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
