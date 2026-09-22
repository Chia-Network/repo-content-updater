"""Regression tests for managed GitHub workflow templates."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEPENDENCY_CURSOR_REVIEW = _REPO_ROOT / "templates" / "dependency-cursor-review.yml"
_TRUSTED_GIT_CHECKOUT_ACTION = (
    _REPO_ROOT / "templates" / "trusted-git-path-checkout-action.yml"
)


class DependencyCursorReviewWorkflowSecurityTest(unittest.TestCase):
    def test_ensure_step_uses_trusted_git_path_checkout_action(self) -> None:
        self.assertTrue(_DEPENDENCY_CURSOR_REVIEW.is_file())
        workflow = _DEPENDENCY_CURSOR_REVIEW.read_text(encoding="utf-8")
        self.assertNotIn("Formatter script present on PR head.", workflow)
        ensure_block = workflow.split("Ensure malware verdict formatter script", 1)[1]
        ensure_block = ensure_block.split("Install Cursor CLI", 1)[0]
        self.assertIn(
            "./.github/actions/trusted-git-path-checkout",
            ensure_block,
            msg="ensure step must call the trusted checkout composite action",
        )
        self.assertNotIn("http.extraheader=AUTHORIZATION", ensure_block)
        self.assertIn(".github/scripts/malware_verdict_formatter.py", ensure_block)

    def test_trusted_git_path_checkout_action_uses_basic_auth_fetch(self) -> None:
        self.assertTrue(_TRUSTED_GIT_CHECKOUT_ACTION.is_file())
        action = _TRUSTED_GIT_CHECKOUT_ACTION.read_text(encoding="utf-8")
        self.assertIn("never executing PR head copy", action)
        self.assertIn('http.extraheader=AUTHORIZATION: basic ${auth_basic}', action)
        self.assertIn('git checkout "FETCH_HEAD" -- "${script}"', action)
        self.assertIn("x-access-token:", action)
        self.assertNotRegex(action, r'if\s+\[\s*-f\s+"?\$?\{?script\}?"?\s*\];\s*then[\s\S]*?exit\s+0')
        self.assertRegex(
            action,
            re.compile(r"Trusted file missing on origin/\$\{default_branch\}", re.MULTILINE),
        )
        self.assertNotRegex(action, r"echo\s+.*\$\{GH_TOKEN\}")


if __name__ == "__main__":
    unittest.main()
