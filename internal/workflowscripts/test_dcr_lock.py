"""Tests for dcr_lock: changed file paths from a diff."""

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

from dcr_lock import changed_files, ioc_patterns, scan_diff, write_diff


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


class WriteDiffTest(unittest.TestCase):
    def test_nul_byte_file_content_is_scanned_as_text(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.dict(os.environ, {"DEPENDABOT_CURSOR_MALWARE_IOC_PATTERNS": '["EVIL_MARKER"]'}),
        ):
            out = Path(tmp)
            (out / "new" / "pkg").mkdir(parents=True)
            (out / "new" / "pkg" / "x.js").write_bytes(b"safe\x00line\nEVIL_MARKER\n")
            self.assertFalse(write_diff(out))
            text = (out / "changes.diff").read_text(encoding="utf-8")
            self.assertNotIn("Binary files", text)
            hits = scan_diff(out / "changes.diff", ioc_patterns())
            self.assertEqual([hit["kind"] for hit in hits], ["ioc"])


if __name__ == "__main__":
    unittest.main()
