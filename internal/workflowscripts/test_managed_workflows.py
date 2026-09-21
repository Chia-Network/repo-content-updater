"""Regression tests for managed GitHub workflow templates."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEPENDENCY_CURSOR_REVIEW = _REPO_ROOT / "templates" / "dependency-cursor-review.yml"


class DependencyCursorReviewWorkflowSecurityTest(unittest.TestCase):
    def test_ensure_step_always_installs_trusted_formatter(self) -> None:
        self.assertTrue(_DEPENDENCY_CURSOR_REVIEW.is_file())
        workflow = _DEPENDENCY_CURSOR_REVIEW.read_text(encoding="utf-8")
        self.assertNotIn("Formatter script present on PR head.", workflow)
        self.assertIn(
            "never executing PR head copy",
            workflow,
            msg="ensure step must overwrite PR-head formatter with default-branch copy",
        )
        self.assertIn('git checkout "FETCH_HEAD" -- "${script}"', workflow)
        ensure_block = workflow.split("Ensure malware verdict formatter script", 1)[1]
        ensure_block = ensure_block.split("Install Cursor CLI", 1)[0]
        self.assertNotRegex(
            ensure_block,
            r'if\s+\[\s*-f\s+"\$script"\s*\];\s*then[\s\S]*?exit\s+0',
        )
        self.assertRegex(
            ensure_block,
            re.compile(
                r'Trusted formatter missing on origin/\$\{default_branch\}',
                re.MULTILINE,
            ),
        )


if __name__ == "__main__":
    unittest.main()
