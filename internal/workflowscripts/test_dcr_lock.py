"""Tests for dcr_lock: changed file lists and hunk parsing from a diff."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import dcr_fetch
from dcr_lock import added_lines, parse_hunks


class DiffParseTest(unittest.TestCase):
    def test_content_line_beginning_with_two_pluses_is_added(self) -> None:
        text = "diff -ruNa old/x new/x\n--- old/x\n+++ new/x\n@@ -1 +1 @@\n-++removed\n+++eval(atob(1))\n"
        hunks = parse_hunks(text)
        self.assertEqual([body for hunk in hunks for kind, body in hunk.lines if kind == "+"], ["++eval(atob(1))"])
        self.assertEqual([body for hunk in hunks for kind, body in hunk.lines if kind == "-"], ["++removed"])
        self.assertEqual([body for _number, body in added_lines(text)], ["++eval(atob(1))"])

    def test_file_header_is_not_added_content(self) -> None:
        text = "diff -ruNa old/x new/x\n--- old/x\n+++ new/x\n@@ -1 +1 @@\n-a\n+b\n"
        hunks = parse_hunks(text)
        self.assertEqual([body for hunk in hunks for kind, body in hunk.lines if kind == "+"], ["b"])
        self.assertEqual([body for hunk in hunks for kind, body in hunk.lines if kind == "-"], ["a"])


class ChangedFilesTest(unittest.TestCase):
    def _note(self, path: str | None) -> str | None:
        """The scope note for a pip head and the given PR files list path."""
        with mock.patch.dict(os.environ, {}, clear=False):
            if path is None:
                os.environ.pop("PR_FILES_PATH", None)
            else:
                os.environ["PR_FILES_PATH"] = path
            files = dcr_fetch._changed_files()
        return "changed file list unavailable" if files is None else dcr_fetch._scope_note("pip", files)

    def test_lockfile_only_list_has_no_scope_note(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            files = Path(tmp) / "files.txt"
            files.write_text("poetry.lock\n", encoding="utf-8")
            self.assertIsNone(self._note(str(files)))

    def test_previous_filename_outside_the_ecosystem_is_named(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            files = Path(tmp) / "files.txt"
            files.write_text("poetry.lock\n.github/workflows/x.yml\n", encoding="utf-8")
            self.assertEqual(
                self._note(str(files)),
                "changed file outside the update ecosystem: .github/workflows/x.yml",
            )

    def test_unavailable_changed_file_lists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty.txt"
            empty.write_text("", encoding="utf-8")
            missing = Path(tmp) / "missing.txt"
            for label, path in (
                ("missing env var", None),
                ("missing file", str(missing)),
                ("empty file", str(empty)),
            ):
                with self.subTest(label=label):
                    self.assertEqual(self._note(path), "changed file list unavailable")

    def test_three_thousand_paths_are_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            files = Path(tmp) / "files.txt"
            files.write_text("\n".join(f"file-{index}" for index in range(3000)), encoding="utf-8")
            self.assertEqual(self._note(str(files)), "changed file list unavailable")


if __name__ == "__main__":
    unittest.main()
