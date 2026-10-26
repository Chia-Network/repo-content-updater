"""Tests for dcr_lock: changed file paths and hunk parsing from a diff."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from dcr_lock import added_lines, changed_files, parse_hunks


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
    def test_both_sides_of_a_rename_are_reported(self) -> None:
        text = (
            "diff --git a/old.txt b/new.txt\n"
            "similarity index 100%\n"
            "rename from old.txt\n"
            "rename to new.txt\n"
            "--- a/old.txt\n"
            "+++ b/new.txt\n"
        )
        self.assertEqual(changed_files(text), ("old.txt", "new.txt"))

    def test_deletion_is_reported_from_the_git_header(self) -> None:
        text = "diff --git a/gone.txt b/gone.txt\ndeleted file mode 100644\n--- a/gone.txt\n+++ /dev/null\n"
        self.assertEqual(changed_files(text), ("gone.txt",))

    def test_quoted_path_with_spaces_is_unquoted(self) -> None:
        text = 'diff --git "a/with space.txt" "b/with space.txt"\n'
        self.assertEqual(changed_files(text), ("with space.txt",))

    def test_unquoted_path_with_spaces_is_kept_whole(self) -> None:
        text = "diff --git a/with space.txt b/with space.txt\n"
        self.assertEqual(changed_files(text), ("with space.txt",))

    def test_duplicate_paths_are_reported_once(self) -> None:
        text = "diff --git a/same.txt b/same.txt\ndiff --git a/same.txt b/same.txt\n"
        self.assertEqual(changed_files(text), ("same.txt",))

    def test_headers_without_a_git_line_are_ignored(self) -> None:
        text = "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-old\n+new\n"
        self.assertEqual(changed_files(text), ())


if __name__ == "__main__":
    unittest.main()
