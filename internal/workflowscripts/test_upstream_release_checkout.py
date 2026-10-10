"""Detach the upstream release before stripping agent-instruction files.

Bugbot 26905c42 on chia-docs #1105: the workflow deleted tracked
instruction files on the default-branch checkout of ``.upstream-dependency``,
then detached ``resolved_to``. That dirties the worktree. Detach aborts when
local changes would be overwritten, and a plain delete of a differing blob is
restored by detach, so the strip has to run on the release tree the agent
reads. A failed detach fails the job instead of reviewing the wrong tree.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOW = _REPO_ROOT / "templates" / "dependency-cursor-review.yml"
_SCAN_SCRIPTS = (
    _REPO_ROOT / "internal" / "workflowscripts" / "upstream_malware_scan.sh",
    _REPO_ROOT / "internal" / "workflowscripts" / "upstream_malware_scan_lib.sh",
    _REPO_ROOT / "internal" / "workflowscripts" / "upstream_malware_scan_findings.sh",
)
_STEP = "Check out upstream release and drop agent instructions"
_INSTRUCTION_RMS = (
    "rm -rf .upstream-dependency/.cursor\n",
    "rm -f .upstream-dependency/.cursorrules\n",
    "rm -f .upstream-dependency/.cursorignore\n",
    "rm -f .upstream-dependency/AGENTS.md\n",
    "rm -f .upstream-dependency/CLAUDE.md\n",
)


def _release_checkout_script() -> str:
    workflow = _WORKFLOW.read_text(encoding="utf-8")
    section = workflow.split(f"- name: {_STEP}\n", 1)[1].split("\n      - name:", 1)[0]
    body: list[str] = []
    started = False
    for line in section.splitlines():
        if not started:
            if line.strip() == "set -euo pipefail":
                started = True
            else:
                continue
        if line.startswith("          "):
            body.append(line[10:])
        elif line == "":
            body.append("")
        else:
            break
    if not body or not started:
        raise AssertionError("release checkout script not found")
    return "\n".join(body) + "\n"


def _run(
    cwd: Path, *args: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    merged.setdefault("GIT_AUTHOR_NAME", "checkout-test")
    merged.setdefault("GIT_AUTHOR_EMAIL", "checkout-test@example.com")
    merged.setdefault("GIT_COMMITTER_NAME", "checkout-test")
    merged.setdefault("GIT_COMMITTER_EMAIL", "checkout-test@example.com")
    if env:
        merged.update(env)
    argv = list(args)
    if argv and argv[0] == "bash":
        argv[0] = shutil.which("bash") or "bash"
    return subprocess.run(
        argv,
        cwd=cwd,
        env=merged,
        check=False,
        capture_output=True,
        text=True,
    )


def _git(repo: Path, *args: str) -> str:
    proc = _run(repo, "git", *args)
    if proc.returncode != 0:
        raise AssertionError(f"git {args} failed\n{proc.stdout}{proc.stderr}")
    return proc.stdout.strip()


def _init_repo(repo: Path) -> None:
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "checkout-test@example.com")
    _git(repo, "config", "user.name", "checkout-test")
    _git(repo, "config", "commit.gpgsign", "false")
    _git(repo, "config", "core.fsmonitor", "false")


def _commit_all(repo: Path, message: str) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", message)


def _write(repo: Path, rel: str, content: str) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


class UpstreamReleaseCheckoutTest(unittest.TestCase):
    def test_workflow_strips_instruction_files_only_after_detach(self) -> None:
        workflow = _WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("Remove upstream agent-instruction files", workflow)
        detach = workflow.index("git -C .upstream-dependency checkout --detach")
        upstream = workflow.index("- name: Checkout upstream repository\n")
        scan = workflow.index("- name: Run upstream malware scan\n")
        gather = workflow.index("- name: Gather local usage hints\n")
        self.assertLess(upstream, scan)
        self.assertLess(scan, detach)
        self.assertLess(detach, gather)
        between = workflow[scan:detach]
        self.assertNotIn("rm -f .upstream-dependency/", between)
        self.assertNotIn("rm -rf .upstream-dependency/", between)
        self.assertNotIn("git checkout", between)
        for needle in _INSTRUCTION_RMS:
            self.assertEqual(workflow.count(needle), 1, needle)
            self.assertLess(detach, workflow.index(needle), needle)
        script = _release_checkout_script()
        self.assertLess(
            script.index("checkout --detach"),
            script.index("rm -f .upstream-dependency/AGENTS.md"),
        )
        self.assertIn("set -euo pipefail", script)
        self.assertIn("Failed to detach .upstream-dependency", script)
        self.assertIn("exit 1", script)
        self.assertNotIn("|| true", script)
        self.assertNotIn("checkout --detach --force", script)
        for scan_path in _SCAN_SCRIPTS:
            text = scan_path.read_text(encoding="utf-8")
            self.assertNotIn("git checkout", text, scan_path.name)
            self.assertNotIn("AGENTS.md", text, scan_path.name)
            self.assertNotIn("CLAUDE.md", text, scan_path.name)

    def test_differing_instruction_file_detaches_release_then_strips(self) -> None:
        """Tracked AGENTS.md differs between the default branch and the tag."""
        with tempfile.TemporaryDirectory() as tmp:
            work, repo, release = self._repo(Path(tmp))
            self._write_report(work, release)
            proc = self._run_script(work)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(_git(repo, "rev-parse", "HEAD"), release)
            self.assertEqual(_git(repo, "rev-parse", "--abbrev-ref", "HEAD"), "HEAD")
            self._assert_instruction_files_gone(repo)
            self.assertEqual(
                (repo / "pkg" / "index.js").read_text(encoding="utf-8"),
                "release code\n",
            )
            self.assertEqual(
                (repo / "pkg" / "release-only.js").read_text(encoding="utf-8"),
                "release only\n",
            )
            self.assertFalse((repo / "pkg" / "main-only.js").exists())

    def test_dirty_instruction_edit_fails_closed_without_stripping(self) -> None:
        """A local edit of the differing instruction file must fail the step."""
        with tempfile.TemporaryDirectory() as tmp:
            work, repo, release = self._repo(Path(tmp))
            _write(repo, "AGENTS.md", "dirty local instructions\n")
            self._write_report(work, release)
            proc = self._run_script(work)
            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            combined = proc.stdout + proc.stderr
            self.assertIn("Failed to detach .upstream-dependency", combined)
            self.assertIn("would be overwritten by checkout", combined)
            self.assertNotEqual(_git(repo, "rev-parse", "HEAD"), release)
            self.assertEqual(
                (repo / "AGENTS.md").read_text(encoding="utf-8"),
                "dirty local instructions\n",
            )
            self.assertTrue((repo / "pkg" / "main-only.js").is_file())
            self.assertFalse((repo / "pkg" / "release-only.js").exists())

    def test_deleted_differing_instruction_file_is_not_the_analyzed_tree(self) -> None:
        """Detach restores a differing blob, so an earlier delete does not stick.

        The workflow must strip after detach. This is the dirty-tree case from
        Bugbot 26905c42: AGENTS.md is tracked, deleted on the default branch,
        and different at the release tag.
        """
        with tempfile.TemporaryDirectory() as tmp:
            work, repo, release = self._repo(Path(tmp))
            (repo / "AGENTS.md").unlink()
            (repo / ".cursor" / "rules" / "rule.mdc").unlink()
            bare = _run(
                work,
                "git",
                "-C",
                ".upstream-dependency",
                "checkout",
                "--detach",
                release,
            )
            self.assertEqual(bare.returncode, 0, bare.stdout + bare.stderr)
            self.assertEqual(
                (repo / "AGENTS.md").read_text(encoding="utf-8"),
                "release agents\n",
            )
            self.assertEqual(
                (repo / ".cursor" / "rules" / "rule.mdc").read_text(encoding="utf-8"),
                "release rule\n",
            )
            _git(repo, "checkout", "--force", "main")
            self._write_report(work, release)
            proc = self._run_script(work)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(_git(repo, "rev-parse", "HEAD"), release)
            self._assert_instruction_files_gone(repo)
            self.assertEqual(
                (repo / "pkg" / "index.js").read_text(encoding="utf-8"),
                "release code\n",
            )

    def test_missing_resolved_to_object_fails_before_strip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work, repo, _release = self._repo(Path(tmp))
            missing = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            self._write_report(work, missing)
            proc = self._run_script(work)
            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("Failed to detach .upstream-dependency", proc.stderr)
            self.assertEqual(
                (repo / "AGENTS.md").read_text(encoding="utf-8"),
                "main agents\n",
            )
            self.assertTrue((repo / ".cursor" / "rules" / "rule.mdc").is_file())
            self.assertEqual(_git(repo, "rev-parse", "--abbrev-ref", "HEAD"), "main")

    def test_unresolved_release_strips_default_branch_without_switching(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work, repo, release = self._repo(Path(tmp))
            self._write_report(work, "")
            proc = self._run_script(work)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertNotEqual(_git(repo, "rev-parse", "HEAD"), release)
            self.assertEqual(_git(repo, "rev-parse", "--abbrev-ref", "HEAD"), "main")
            self._assert_instruction_files_gone(repo)
            self.assertEqual(
                (repo / "pkg" / "index.js").read_text(encoding="utf-8"),
                "main code\n",
            )
            self.assertTrue((repo / "pkg" / "main-only.js").is_file())

    def _repo(self, root: Path) -> tuple[Path, Path, str]:
        work = root / "work"
        repo = work / ".upstream-dependency"
        work.mkdir()
        _init_repo(repo)
        _write(repo, "AGENTS.md", "release agents\n")
        _write(repo, "CLAUDE.md", "release claude\n")
        _write(repo, ".cursorrules", "release cursorrules\n")
        _write(repo, ".cursorignore", "release cursorignore\n")
        _write(repo, ".cursor/rules/rule.mdc", "release rule\n")
        _write(repo, "pkg/index.js", "release code\n")
        _write(repo, "pkg/release-only.js", "release only\n")
        _commit_all(repo, "release")
        release = _git(repo, "rev-parse", "HEAD")
        _git(repo, "tag", "v1.2.3")
        _write(repo, "AGENTS.md", "main agents\n")
        _write(repo, "CLAUDE.md", "main claude\n")
        _write(repo, ".cursorrules", "main cursorrules\n")
        _write(repo, ".cursorignore", "main cursorignore\n")
        _write(repo, ".cursor/rules/rule.mdc", "main rule\n")
        _write(repo, "pkg/index.js", "main code\n")
        _write(repo, "pkg/main-only.js", "main only\n")
        (repo / "pkg" / "release-only.js").unlink()
        _commit_all(repo, "main moves ahead of the release")
        self.assertNotEqual(_git(repo, "rev-parse", "HEAD"), release)
        self.assertIn("release agents", _git(repo, "show", f"{release}:AGENTS.md"))
        self.assertIn("main agents", (repo / "AGENTS.md").read_text(encoding="utf-8"))
        return work, repo, release

    def _write_report(self, work: Path, resolved_to: str) -> None:
        report = work / "malware_scan_report.json"
        report.write_text(
            json.dumps({"resolved_to": resolved_to}) + "\n",
            encoding="utf-8",
        )

    def _run_script(self, work: Path) -> subprocess.CompletedProcess[str]:
        jq = shutil.which("jq")
        self.assertIsNotNone(jq, "jq is required to read resolved_to")
        script = work / "checkout-release.sh"
        script.write_text(_release_checkout_script(), encoding="utf-8")
        return _run(work, "bash", str(script))

    def _assert_instruction_files_gone(self, repo: Path) -> None:
        for rel in (
            "AGENTS.md",
            "CLAUDE.md",
            ".cursorrules",
            ".cursorignore",
            ".cursor/rules/rule.mdc",
        ):
            self.assertFalse((repo / rel).exists(), rel)
        self.assertFalse((repo / ".cursor").exists())


if __name__ == "__main__":
    unittest.main()
