"""Job outputs go to a fresh directory outside the PR-head checkout; scripts never import from it."""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

import dependency_update_coverage as coverage

_HERE = Path(__file__).resolve().parent
_WORKFLOW = _HERE.parents[1] / "templates" / "dependency-cursor-review.yml"
_TARGET_TEXT = "outside the checkout\n"


def _step_script(step: str) -> str:
    workflow = _WORKFLOW.read_text(encoding="utf-8")
    block = workflow.split(f"- name: {step}\n", 1)[1].split("\n      - name: ", 1)[0]
    script = block.split("        run: |\n", 1)[1].split("\n  dependency-review", 1)[0]
    return textwrap.dedent(script)


class _Checkout(unittest.TestCase):
    """A PR-head checkout as cwd, with a fresh output directory beside it."""

    def setUp(self) -> None:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.outside = root / "outside"
        self.outside.mkdir()
        self.out = root / "dcr-out"
        self.out.mkdir()
        self.checkout = root / "checkout"
        self.checkout.mkdir()
        self.enterContext(contextlib.chdir(self.checkout))

    def link_dir(self, name: str) -> Path:
        target = self.outside / name
        target.mkdir()
        (target / "marker").write_text(_TARGET_TEXT, encoding="utf-8")
        os.symlink(target, name)
        return target

    def env(self, **extra: str) -> dict[str, str]:
        return {"PATH": os.environ["PATH"], "DCR_OUT": str(self.out), **extra}

    def assert_only_in_out(self, *names: str) -> None:
        for name in names:
            self.assertTrue((self.out / name).is_file(), name)
        self.assertEqual(sorted(p.name for p in self.checkout.iterdir() if p.name in names), [])


class CoverageOutputTest(_Checkout):
    def run_coverage(self) -> None:
        with (
            patch.dict(os.environ, self.env(GITHUB_OUTPUT=str(self.outside / "github_output.txt"))),
            patch.object(coverage, "_clone", lambda *_args: False),
        ):
            coverage.main()

    def test_report_is_written_to_the_output_dir(self) -> None:
        self.run_coverage()
        self.assert_only_in_out("malware_scan_report.json", "malware_scan_summary.md")
        report = json.loads((self.out / "malware_scan_report.json").read_text(encoding="utf-8"))
        self.assertIs(report["scan_conclusive"], False)

    def test_scan_work_dir_link_is_unlinked_not_emptied(self) -> None:
        target = self.link_dir(".dcr-dependency-scans")
        self.run_coverage()
        self.assertEqual(sorted(p.name for p in target.iterdir()), ["marker"])
        self.assertFalse(Path(".dcr-dependency-scans").exists())

    def test_kept_checkout_link_is_unlinked_not_emptied(self) -> None:
        target = self.link_dir(".upstream-dependency")
        scanned = Path("scan")
        (scanned / ".upstream-dependency").mkdir(parents=True)
        record = {"package_name": "left-pad", "upstream_repo": "left-pad/left-pad", "resolved_to": "b"}
        with patch.object(coverage, "agent_target", lambda records: coverage._identity(records[0])):
            coverage._keep_checkout([record], [(record, scanned)])
        self.assertFalse(Path(".upstream-dependency").is_symlink())
        self.assertTrue(Path(".upstream-dependency").is_dir())
        self.assertEqual(sorted(p.name for p in target.iterdir()), ["marker"])

    def test_isolated_run_does_not_import_from_the_checkout(self) -> None:
        """python3 -I keeps the PR-head cwd off sys.path; siblings come from the script's own directory."""
        for name in ("dependency_manifest_diff.py", "dependency_cursor_review_ecosystems.py"):
            Path(name).write_text("raise SystemExit('PR head imported')\n", encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, "-I", str(_HERE / "dependency_update_coverage.py")],
            check=False,
            capture_output=True,
            text=True,
            env=self.env(),
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        report = json.loads((self.out / "malware_scan_report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["not_scanned_reason"], "unresolved")
        self.assertEqual(report["path"], "pull request diff")


class ScanJobOutputTest(_Checkout):
    def test_prompts_are_written_to_the_output_dir(self) -> None:
        subprocess.run(
            [sys.executable, "-I", str(_HERE / "dependency_cursor_review_prompts.py")],
            check=True,
            capture_output=True,
            env=self.env(PACKAGE_NAME="left-pad"),
        )
        self.assert_only_in_out("cursor_prompt_malware.txt", "cursor_prompt_compatibility.txt")

    def test_dependabot_context_is_written_to_the_output_dir(self) -> None:
        script = _HERE / "dependency-cursor-review-dependabot-context.js"
        subprocess.run(
            ["node", "-e", f"require({json.dumps(str(script))})()"],
            check=True,
            capture_output=True,
            env=self.env(PR_BODY="Bumps left-pad from 1.2.3 to 1.2.4."),
        )
        self.assert_only_in_out(
            "dependabot_comment_context.json",
            "dependabot_release_notes.md",
            "dependabot_commits.md",
        )

    def test_usage_hints_are_written_to_the_output_dir(self) -> None:
        subprocess.run(
            ["bash", "-euo", "pipefail", "-c", _step_script("Gather local usage hints")],
            check=True,
            env=self.env(PACKAGE_NAME=""),
        )
        self.assert_only_in_out("package_usage.txt")


class AgentOutputTest(_Checkout):
    _NAMES = ("cursor_output_malware.json", "cursor_output_compatibility.json")

    _AGENT = '#!/bin/sh\necho \'{"type":"result","result":"ok"}\'\n'
    # Fails on a prompt read from stdin; answers a prompt passed as its last argument, which it keeps.
    _STDIN_FAILS = (
        '#!/bin/sh\n[ "$#" -eq 7 ] || exit 1\nprintf %s "$7" >>"$ARGV_PROMPTS"\n'
        'echo \'{"type":"result","result":"ok"}\'\n'
    )

    def _run_agent_step(self, key: str, agent_script: str = _AGENT, prompt: str = "prompt\n", **extra: str) -> Path:
        bin_dir = self.outside / "bin"
        bin_dir.mkdir()
        agent = bin_dir / "agent"
        agent.write_text(agent_script, encoding="utf-8")
        agent.chmod(0o755)
        Path("dcr-scan-input").mkdir()
        for name in ("cursor_prompt_malware.txt", "cursor_prompt_compatibility.txt"):
            (Path("dcr-scan-input") / name).write_text(prompt, encoding="utf-8")
        runner_temp = self.outside / "runner-temp"
        runner_temp.mkdir()
        env = {
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "CURSOR_API_KEY": key,
            "RUNNER_TEMP": str(runner_temp),
            **extra,
        }
        subprocess.run(["bash", "-c", _step_script("Run Cursor agent")], check=True, env=env)
        return runner_temp / "dcr-out"

    def test_agent_outputs_are_written_to_the_output_dir(self) -> None:
        out = self._run_agent_step("key")
        self.assertEqual(sorted(p.name for p in self.checkout.iterdir()), ["dcr-scan-input"])
        for name in self._NAMES:
            self.assertEqual(json.loads((out / name).read_text(encoding="utf-8"))["result"], "ok")

    def test_agent_step_python_ignores_the_checkout_and_pythonpath(self) -> None:
        """A json.py or sys.py in the working directory or on PYTHONPATH is never imported, fallback included."""
        planted = self.outside / "planted"
        planted.mkdir()
        hit = self.outside / "imported"
        for directory in (self.checkout, planted):
            for module in ("json.py", "sys.py"):
                (directory / module).write_text(f"open({str(hit)!r}, 'a').write('{module}')\n", encoding="utf-8")
        prompts = self.outside / "argv-prompts"
        out = self._run_agent_step(
            "key", self._STDIN_FAILS, "p" * 60001, PYTHONPATH=str(planted), ARGV_PROMPTS=str(prompts)
        )
        self.assertFalse(hit.exists())
        for name in self._NAMES:
            self.assertEqual(json.loads((out / name).read_text(encoding="utf-8"))["result"], "ok")
        notice = "\n\n[Prompt truncated for CLI argument compatibility.]"
        self.assertEqual(prompts.read_text(encoding="utf-8"), ("p" * 60000 + notice) * 2)

    def test_skipped_agent_outputs_are_written_to_the_output_dir(self) -> None:
        out = self._run_agent_step("")
        for name in self._NAMES:
            self.assertIs(json.loads((out / name).read_text(encoding="utf-8"))["complete"], False)


if __name__ == "__main__":
    unittest.main()
