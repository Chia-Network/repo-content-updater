"""Requirements-file includer discovery over a real tracked tree."""

from __future__ import annotations

import contextlib
import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import dependency_cursor_review_upstream as upstream
import dependency_update_coverage as coverage
from test_dependency_update_coverage import _clean, _found, _git, _git_repo, _plan

_CHIA = "https://pypi.chia.net/simple/"
_BASE = f"-i {_CHIA}\nchiapos==2.0.4 --hash=sha256:abc\n"


def _write(repo: Path, rel: str, data: bytes, message: str) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    _git(repo, "add", rel)
    _git(repo, "commit", "-m", message)


def _symlink(repo: Path, rel: str, target: str, message: str) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(target, path)
    _git(repo, "add", rel)
    _git(repo, "commit", "-m", message)


def _run(repo: Path, *, trusted_host: str = "") -> dict:
    root = repo.parent
    output = root / "github_output.txt"
    plan = _plan(("pip", ".", "chiapos", "2.0.3", "2.0.4"), hashed=("requirements.txt",))
    with (
        contextlib.chdir(repo),
        patch.dict(os.environ, {"GITHUB_OUTPUT": str(output), "DCR_OUT": str(root)}),
        patch.object(coverage, "_plan", return_value=plan),
        patch.object(
            coverage._ecosystems,
            "upstream_repo",
            lambda _ecosystem, name, _version: _found(f"upstream/{name}"),
        ),
        patch.object(
            coverage,
            "_scan_one",
            lambda target, *_args: _clean(target.package, target.repo.slug),
        ),
        patch.object(upstream, "trusted_python_index", lambda *_args: trusted_host),
    ):
        coverage.main()
    return json.loads((root / "malware_scan_report.json").read_text(encoding="utf-8"))


class IncluderDiscoveryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(TemporaryDirectory())) / "repo"
        _git_repo(self.root)

    def test_a_symlink_alias_of_the_base_leaves_it_unread(self) -> None:
        _write(self.root, "requirements.txt", _BASE.encode(), "base")
        _symlink(self.root, "link.txt", "requirements.txt", "alias")
        _write(self.root, "dev.txt", b"-r link.txt\n", "dev")
        report = _run(self.root)
        self.assertEqual(report["trusted_packages"], [])
        self.assertIs(report["scan_conclusive"], False)

    def test_a_utf16_requirements_file_leaves_the_base_unread(self) -> None:
        _write(self.root, "requirements.txt", _BASE.encode(), "base")
        _write(
            self.root,
            "dev-requirements.txt",
            "chiapos==2.0.4\n".encode("utf-16"),
            "dev",
        )
        report = _run(self.root)
        self.assertEqual(report["trusted_packages"], [])
        self.assertIs(report["scan_conclusive"], False)

    def test_a_nul_byte_in_a_requirements_file_leaves_the_base_unread(self) -> None:
        _write(self.root, "requirements.txt", _BASE.encode(), "base")
        _write(self.root, "dev-requirements.txt", b"# note\x00\n", "dev")
        report = _run(self.root)
        self.assertEqual(report["trusted_packages"], [])
        self.assertIs(report["scan_conclusive"], False)

    def test_a_non_utf8_readme_mention_does_not_crash_and_is_not_trusted(self) -> None:
        _write(self.root, "requirements.txt", _BASE.encode(), "base")
        _write(self.root, "README.md", b"See requirements.txt for caf\xe9.\n", "readme")
        report = _run(self.root)
        self.assertEqual(report["trusted_packages"], [])
        self.assertIs(report["scan_conclusive"], False)

    def test_ordinary_utf8_text_files_keep_the_base_trusted(self) -> None:
        _write(self.root, "requirements.txt", _BASE.encode(), "base")
        _write(self.root, "LICENSE.txt", b"license text\n", "license")
        _write(self.root, "docs/notes.txt", b"ordinary notes\n", "notes")
        report = _run(self.root, trusted_host="pypi.chia.net")
        self.assertEqual(
            [(item["name"], item["index"]) for item in report["trusted_packages"]],
            [("chiapos", "pypi.chia.net")],
        )


if __name__ == "__main__":
    unittest.main()
