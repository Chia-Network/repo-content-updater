"""Outputs written into the PR-head checkout replace a link at their name instead of following it."""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import dependency_update_coverage as coverage

_HERE = Path(__file__).resolve().parent
_WORKFLOW = _HERE.parents[1] / "templates" / "dependency-cursor-review.yml"
_TARGET_TEXT = "outside the checkout\n"
_UPDATE = {
    "packageName": "left-pad",
    "fromVersion": "1.2.3",
    "toVersion": "1.2.4",
    "upstreamRepo": "left-pad/left-pad",
}


def _step_script(step: str) -> str:
    workflow = _WORKFLOW.read_text(encoding="utf-8")
    block = workflow.split(f"- name: {step}\n", 1)[1].split("\n      - name: ", 1)[0]
    script = block.split("        run: |\n", 1)[1].split("\n  dependency-review", 1)[0]
    return textwrap.dedent(script)


class _LinkedCheckout(unittest.TestCase):
    """A checkout whose fixed output names are links into a directory outside it."""

    def setUp(self) -> None:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.outside = root / "outside"
        self.outside.mkdir()
        self.checkout = root / "checkout"
        self.checkout.mkdir()
        self.enterContext(contextlib.chdir(self.checkout))

    def link_file(self, name: str) -> Path:
        target = self.outside / name
        target.write_text(_TARGET_TEXT, encoding="utf-8")
        os.symlink(target, name)
        return target

    def link_dir(self, name: str) -> Path:
        target = self.outside / name
        target.mkdir()
        (target / "marker").write_text(_TARGET_TEXT, encoding="utf-8")
        os.symlink(target, name)
        return target

    def assert_replaced(self, name: str, target: Path) -> None:
        self.assertFalse(Path(name).is_symlink(), name)
        self.assertTrue(Path(name).exists(), name)
        if target.is_dir():
            self.assertEqual((target / "marker").read_text(encoding="utf-8"), _TARGET_TEXT)
        else:
            self.assertEqual(target.read_text(encoding="utf-8"), _TARGET_TEXT, name)

    @contextlib.contextmanager
    def github_output(self) -> Iterator[None]:
        output = self.outside.parent / "github_output.txt"
        with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}):
            yield


class CoverageOutputLinksTest(_LinkedCheckout):
    def test_scan_work_dir_link_is_unlinked_not_emptied(self) -> None:
        target = self.link_dir(".dcr-dependency-scans")
        Path("dependency_updates.json").write_text(json.dumps([_UPDATE]), encoding="utf-8")
        with self.github_output(), patch.object(coverage, "_clone", lambda *_args: False):
            coverage.main()
        self.assertEqual(sorted(p.name for p in target.iterdir()), ["marker"])
        self.assertFalse(Path(".dcr-dependency-scans").exists())

    def test_report_links_are_replaced(self) -> None:
        names = ("malware_scan_report.json", "malware_scan_summary.md")
        targets = {name: self.link_file(name) for name in names}
        Path("dependency_updates.json").write_text(json.dumps([_UPDATE]), encoding="utf-8")
        with self.github_output(), patch.object(coverage, "_clone", lambda *_args: False):
            coverage.main()
        for name, target in targets.items():
            self.assert_replaced(name, target)
        self.assertIs(json.loads(Path(names[0]).read_text(encoding="utf-8"))["scan_conclusive"], False)

    def test_kept_checkout_link_is_unlinked_not_emptied(self) -> None:
        target = self.link_dir(".upstream-dependency")
        scanned = Path("scan")
        (scanned / ".upstream-dependency").mkdir(parents=True)
        record = {"package_name": "left-pad", "upstream_repo": "left-pad/left-pad", "resolved_to": "b"}
        with patch.object(coverage, "agent_target", lambda records: coverage._identity(records[0])):
            coverage._keep_checkout([record], [(record, scanned)])
        self.assert_replaced(".upstream-dependency", target)
        self.assertEqual(sorted(p.name for p in target.iterdir()), ["marker"])


class ScanJobOutputLinksTest(_LinkedCheckout):
    def test_prompt_links_are_replaced(self) -> None:
        names = ("cursor_prompt_malware.txt", "cursor_prompt_compatibility.txt")
        targets = {name: self.link_file(name) for name in names}
        subprocess.run(
            [sys.executable, "-I", str(_HERE / "dependency_cursor_review_prompts.py")],
            check=True,
            capture_output=True,
            env={"PATH": os.environ["PATH"], "PACKAGE_NAME": "left-pad"},
        )
        for name, target in targets.items():
            self.assert_replaced(name, target)

    def test_dependabot_context_links_are_replaced(self) -> None:
        names = (
            "dependency_updates.json",
            "dependabot_comment_context.json",
            "dependabot_release_notes.md",
            "dependabot_commits.md",
        )
        targets = {name: self.link_file(name) for name in names}
        script = _HERE / "dependency-cursor-review-dependabot-context.js"
        subprocess.run(
            ["node", "-e", f"require({json.dumps(str(script))})({{core: {{warning() {{}}, setOutput() {{}}}}}})"],
            check=True,
            capture_output=True,
            env={"PATH": os.environ["PATH"], "PR_TITLE": "Bump left-pad from 1.2.3 to 1.2.4"},
        )
        for name, target in targets.items():
            self.assert_replaced(name, target)
        self.assertEqual(sorted(p.name for p in Path(".").iterdir() if p.name.startswith(".dcr-publish-")), [])

    def test_workflow_scan_step_links_are_replaced(self) -> None:
        steps = {
            "Gather local usage hints": "package_usage.txt",
            "Build Cursor prompts": "upstream_changed_files.txt",
        }
        for step, name in steps.items():
            with self.subTest(step=step):
                target = self.link_file(name)
                # The trusted script runs are covered above; keep the step's own writes.
                script = "\n".join(
                    line for line in _step_script(step).splitlines() if "trusted-dcr-scripts" not in line
                )
                subprocess.run(
                    ["bash", "-euo", "pipefail", "-c", script], check=True, env={**os.environ, "PACKAGE_NAME": ""}
                )
                self.assert_replaced(name, target)

    def test_changed_files_content_is_preserved(self) -> None:
        expected = "a/one.js\nb/two.js\n"
        Path("upstream_changed_files.txt").write_text(expected, encoding="utf-8")
        script = "\n".join(
            line for line in _step_script("Build Cursor prompts").splitlines() if "trusted-dcr-scripts" not in line
        )
        subprocess.run(["bash", "-euo", "pipefail", "-c", script], check=True, env={**os.environ})
        self.assertFalse(Path("upstream_changed_files.txt").is_symlink())
        self.assertEqual(Path("upstream_changed_files.txt").read_text(encoding="utf-8"), expected)


class AgentOutputLinksTest(_LinkedCheckout):
    _NAMES = ("cursor_output_malware.json", "cursor_output_compatibility.json")

    def _run_agent_step(self, key: str) -> None:
        bin_dir = self.outside.parent / "bin"
        bin_dir.mkdir()
        agent = bin_dir / "agent"
        agent.write_text('#!/bin/sh\necho \'{"type":"result","result":"ok"}\'\n', encoding="utf-8")
        agent.chmod(0o755)
        Path("dcr-scan-input").mkdir()
        for name in ("cursor_prompt_malware.txt", "cursor_prompt_compatibility.txt"):
            (Path("dcr-scan-input") / name).write_text("prompt\n", encoding="utf-8")
        env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "CURSOR_API_KEY": key}
        subprocess.run(["bash", "-c", _step_script("Run Cursor agent")], check=True, env=env)

    def test_agent_output_and_stream_links_are_replaced(self) -> None:
        names = (*self._NAMES, *(f"{name}.stream" for name in self._NAMES))
        targets = {name: self.link_file(name) for name in names}
        self._run_agent_step("key")
        for name in self._NAMES:
            self.assert_replaced(name, targets[name])
            self.assertEqual(json.loads(Path(name).read_text(encoding="utf-8"))["result"], "ok")
        for name in names[2:]:
            self.assertEqual(targets[name].read_text(encoding="utf-8"), _TARGET_TEXT, name)

    def test_skipped_agent_output_links_are_replaced(self) -> None:
        targets = {name: self.link_file(name) for name in self._NAMES}
        self._run_agent_step("")
        for name, target in targets.items():
            self.assert_replaced(name, target)
            self.assertIs(json.loads(Path(name).read_text(encoding="utf-8"))["complete"], False)


if __name__ == "__main__":
    unittest.main()
