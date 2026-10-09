"""trusted-git-path-checkout fails closed and can extract into an isolated directory."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_ACTION = _REPO_ROOT / "templates" / "trusted-git-path-checkout-action.yml"


def _action_bash() -> str:
    lines = _ACTION.read_text(encoding="utf-8").splitlines()
    start = next(index for index, line in enumerate(lines) if line.strip() == "set -euo pipefail")
    body: list[str] = []
    for line in lines[start:]:
        if line.startswith("        "):
            body.append(line[8:])
        elif line == "":
            body.append("")
        else:
            break
    return "\n".join(body) + "\n"


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "checkout-test",
            "GIT_AUTHOR_EMAIL": "checkout-test@example.com",
            "GIT_COMMITTER_NAME": "checkout-test",
            "GIT_COMMITTER_EMAIL": "checkout-test@example.com",
        }
    )
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def _init_origin_checkout(root: Path) -> Path:
    origin = root / "origin.git"
    work = root / "work"
    subprocess.run(["git", "init", "--bare", "-b", "main", str(origin)], check=True, capture_output=True)
    work.mkdir()
    init = subprocess.run(["git", "init", "-b", "main", str(work)], check=False, capture_output=True, text=True)
    if init.returncode != 0:
        raise AssertionError(init.stderr)
    _git(work, "config", "user.email", "checkout-test@example.com")
    _git(work, "config", "user.name", "checkout-test")
    added = _git(work, "remote", "add", "origin", str(origin))
    if added.returncode != 0:
        raise AssertionError(added.stderr)
    return work


def _run_action(work: Path, **env: str) -> subprocess.CompletedProcess[str]:
    script = work / "trusted-checkout.sh"
    script.write_text(_action_bash(), encoding="utf-8")
    merged = os.environ.copy()
    merged.update({"GH_TOKEN": "dummy-token", "TRUSTED_REF": "main"})
    merged.update(env)
    return subprocess.run(
        ["bash", str(script)],
        cwd=work,
        check=False,
        capture_output=True,
        text=True,
        env=merged,
    )


class TrustedGitPathCheckoutTest(unittest.TestCase):
    def test_empty_manifest_fails_and_leaves_pr_script(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work = _init_origin_checkout(Path(tmp))
            manifest = work / "trusted.paths"
            manifest.write_text("\n  \n\t\n", encoding="utf-8")
            script = work / "scripts" / "scan.sh"
            script.parent.mkdir()
            script.write_text("echo trusted\n", encoding="utf-8")
            _git(work, "add", "trusted.paths", "scripts/scan.sh")
            commit = _git(work, "commit", "-m", "trusted")
            self.assertEqual(commit.returncode, 0, commit.stderr)
            push = _git(work, "push", "origin", "main")
            self.assertEqual(push.returncode, 0, push.stderr)
            script.write_text("echo pr-head\n", encoding="utf-8")

            proc = _run_action(work, PATHS_MANIFEST="trusted.paths", CHECKOUT_PATH="", CHECKOUT_PATHS="", CHECKOUT_DEST="")
            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("empty or whitespace-only", proc.stdout + proc.stderr)
            self.assertEqual(script.read_text(encoding="utf-8"), "echo pr-head\n")

    def test_dest_extracts_trusted_bytes_without_replacing_pr_script(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = _init_origin_checkout(root)
            manifest = work / "trusted.paths"
            manifest.write_text("scripts/scan.sh\n", encoding="utf-8")
            script = work / "scripts" / "scan.sh"
            script.parent.mkdir()
            script.write_text("echo trusted\n", encoding="utf-8")
            _git(work, "add", "trusted.paths", "scripts/scan.sh")
            self.assertEqual(_git(work, "commit", "-m", "trusted").returncode, 0)
            self.assertEqual(_git(work, "push", "origin", "main").returncode, 0)
            script.write_text("echo pr-head\n", encoding="utf-8")
            dest = root / "isolated"

            proc = _run_action(
                work,
                PATHS_MANIFEST="trusted.paths",
                CHECKOUT_PATH="",
                CHECKOUT_PATHS="",
                CHECKOUT_DEST=str(dest),
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(script.read_text(encoding="utf-8"), "echo pr-head\n")
            self.assertEqual((dest / "scripts" / "scan.sh").read_text(encoding="utf-8"), "echo trusted\n")


if __name__ == "__main__":
    unittest.main()
