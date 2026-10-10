"""upstream_release_checkout.sh detaches the release, then strips instruction files."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent / "upstream_release_checkout.sh"


def _run(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(
        GIT_AUTHOR_NAME="checkout-test",
        GIT_AUTHOR_EMAIL="checkout-test@example.com",
        GIT_COMMITTER_NAME="checkout-test",
        GIT_COMMITTER_EMAIL="checkout-test@example.com",
    )
    argv = [shutil.which("bash") or "bash", *args[1:]] if args and args[0] == "bash" else list(args)
    return subprocess.run(argv, cwd=cwd, env=env, check=False, capture_output=True, text=True)


def _git(repo: Path, *args: str) -> str:
    proc = _run(repo, "git", *args)
    if proc.returncode != 0:
        raise AssertionError(f"git {args} failed\n{proc.stderr}")
    return proc.stdout.strip()


def _init(repo: Path) -> None:
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "checkout-test@example.com")
    _git(repo, "config", "user.name", "checkout-test")
    _git(repo, "config", "commit.gpgsign", "false")
    _git(repo, "config", "core.fsmonitor", "false")


def _write(repo: Path, rel: str, text: str) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _commit(repo: Path, message: str) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", message)


class UpstreamReleaseCheckoutTest(unittest.TestCase):
    def _tree(self, root: Path) -> tuple[Path, Path, str]:
        work, repo = root / "work", root / "work" / ".upstream-dependency"
        work.mkdir()
        _init(repo)
        for rel, text in {
            "AGENTS.md": "release agents\n",
            "CLAUDE.md": "release claude\n",
            ".cursorrules": "release rules\n",
            "pkg/AGENTS.md": "nested agents\n",
            "pkg/.cursor/skills/x/SKILL.md": "cursor skill\n",
            ".agents/skills/x/SKILL.md": "agents skill\n",
            "pkg/index.js": "release code\n",
        }.items():
            _write(repo, rel, text)
        _commit(repo, "release")
        release = _git(repo, "rev-parse", "HEAD")
        _git(repo, "tag", "-a", "v1.2.3", "-m", "release")
        _git(repo, "branch", "release")
        for rel, text in {
            "AGENTS.md": "main agents\n",
            "CLAUDE.md": "main claude\n",
            ".cursorrules": "main rules\n",
            "pkg/AGENTS.md": "main nested\n",
            "pkg/.cursor/skills/x/SKILL.md": "main skill\n",
            ".agents/skills/x/SKILL.md": "main skill\n",
            "pkg/index.js": "main code\n",
        }.items():
            _write(repo, rel, text)
        _commit(repo, "main")
        return work, repo, release

    def _report(self, work: Path, payload: dict) -> None:
        (work / "malware_scan_report.json").write_text(json.dumps(payload) + "\n", encoding="utf-8")

    def _script(self, work: Path) -> subprocess.CompletedProcess[str]:
        self.assertIsNotNone(shutil.which("jq"))
        return _run(work, "bash", str(_SCRIPT))

    def test_differing_blob_detaches_and_strips_nested_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work, repo, release = self._tree(Path(tmp))
            scan = work / ".malware-scan" / "at-to-ref"
            _write(scan, "AGENTS.md", "scan copy\n")
            self._report(work, {"resolved_to": release})
            proc = self._script(work)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(_git(repo, "rev-parse", "HEAD"), release)
            self.assertFalse((work / ".malware-scan").exists())
            for rel in (
                "AGENTS.md",
                "CLAUDE.md",
                ".cursorrules",
                "pkg/AGENTS.md",
                "pkg/.cursor/skills/x/SKILL.md",
                ".agents/skills/x/SKILL.md",
            ):
                self.assertFalse((repo / rel).exists(), rel)
            self.assertEqual((repo / "pkg" / "index.js").read_text(encoding="utf-8"), "release code\n")

    def test_dirty_edit_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work, repo, release = self._tree(Path(tmp))
            _write(repo, "AGENTS.md", "dirty local\n")
            self._report(work, {"resolved_to": release})
            proc = self._script(work)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("would be overwritten by checkout", proc.stderr)
            self.assertEqual((repo / "AGENTS.md").read_text(encoding="utf-8"), "dirty local\n")
            self.assertNotEqual(_git(repo, "rev-parse", "HEAD"), release)

    def test_missing_object_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work, repo, _release = self._tree(Path(tmp))
            self._report(work, {"resolved_to": "a" * 40})
            proc = self._script(work)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("Failed to resolve upstream release", proc.stderr)
            self.assertEqual((repo / "AGENTS.md").read_text(encoding="utf-8"), "main agents\n")
            self.assertEqual(_git(repo, "rev-parse", "--abbrev-ref", "HEAD"), "main")

    def test_empty_resolved_to_removes_checkout_and_scan_dir(self) -> None:
        payloads = ({"resolved_to": ""}, {"resolved_to": None}, {})
        for payload in payloads:
            with tempfile.TemporaryDirectory() as tmp:
                work, repo, _release = self._tree(Path(tmp))
                _write(work / ".malware-scan" / "at-to-ref", "AGENTS.md", "copy\n")
                self._report(work, payload)
                proc = self._script(work)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertFalse(repo.exists())
                self.assertFalse((work / ".malware-scan").exists())

    def test_symlinks_are_unlinked_without_touching_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root / "outside"
            _write(outside, "AGENTS.md", "outside agents\n")
            _write(outside, "keep.txt", "keep\n")
            work, repo = root / "work", root / "work" / ".upstream-dependency"
            work.mkdir()
            _init(repo)
            _write(repo, "pkg/index.js", "release code\n")
            _write(repo, "pkg/AGENTS.md", "nested\n")
            (repo / "AGENTS.md").symlink_to(outside / "AGENTS.md")
            (repo / ".codex").symlink_to(outside, target_is_directory=True)
            (repo / "ext").symlink_to(outside, target_is_directory=True)
            _commit(repo, "release")
            release = _git(repo, "rev-parse", "HEAD")
            _write(repo, "pkg/index.js", "main code\n")
            _commit(repo, "main")
            self._report(work, {"resolved_to": release})
            proc = self._script(work)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertFalse((repo / "AGENTS.md").exists())
            self.assertFalse((repo / ".codex").exists())
            self.assertFalse((repo / "pkg" / "AGENTS.md").exists())
            self.assertTrue((repo / "ext").is_symlink())
            self.assertEqual((outside / "AGENTS.md").read_text(encoding="utf-8"), "outside agents\n")
            self.assertEqual((outside / "keep.txt").read_text(encoding="utf-8"), "keep\n")

    def test_annotated_tag_object_and_branch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work, repo, release = self._tree(Path(tmp))
            tag_object = _git(repo, "rev-parse", "v1.2.3")
            self.assertNotEqual(tag_object, release)
            for value in ("v1.2.3", tag_object, "release"):
                _git(repo, "checkout", "--force", "main")
                self._report(work, {"resolved_to": value})
                proc = self._script(work)
                self.assertEqual(proc.returncode, 0, f"{value}\n{proc.stderr}")
                self.assertEqual(_git(repo, "rev-parse", "HEAD"), release)
                self.assertFalse((repo / "pkg" / "AGENTS.md").exists())
                self.assertEqual((repo / "pkg" / "index.js").read_text(encoding="utf-8"), "release code\n")


if __name__ == "__main__":
    unittest.main()
