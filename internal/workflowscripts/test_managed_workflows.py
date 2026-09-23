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
    def _post_checkout_section(self) -> str:
        workflow = _DEPENDENCY_CURSOR_REVIEW.read_text(encoding="utf-8")
        return workflow.split("Checkout repository", 1)[1]

    def test_composite_action_bootstrapped_from_trusted_ref_before_uses(self) -> None:
        self.assertTrue(_DEPENDENCY_CURSOR_REVIEW.is_file())
        section = self._post_checkout_section()
        bootstrap = section.split(
            "Install trusted git path checkout action definition", 1
        )[1].split("Ensure malware verdict formatter script", 1)[0]
        ensure = section.split("Ensure malware verdict formatter script", 1)[1].split(
            "Install Cursor CLI", 1
        )[0]
        self.assertNotIn("Formatter script present on PR head.", section)
        self.assertIn(
            "not PR head definition",
            bootstrap,
            msg="bootstrap must overwrite composite action from trusted ref",
        )
        self.assertIn('http.extraheader=AUTHORIZATION: basic ${auth_basic}', bootstrap)
        self.assertIn(
            'git checkout "FETCH_HEAD" -- "${action_file}"',
            bootstrap,
        )
        self.assertIn(".github/actions/trusted-git-path-checkout/action.yml", bootstrap)
        self.assertNotIn("http.extraheader=AUTHORIZATION", ensure)
        self.assertIn(
            "./.github/actions/trusted-git-path-checkout",
            ensure,
            msg="formatter ensure uses composite after trusted bootstrap",
        )
        self.assertIn(".github/scripts/malware_verdict_formatter.py", ensure)
        self.assertLess(
            section.index("Install trusted git path checkout action definition"),
            section.index("Ensure malware verdict formatter script"),
        )

    def test_malware_formatter_imported_from_trusted_file_not_scripts_syspath(self) -> None:
        workflow = _DEPENDENCY_CURSOR_REVIEW.read_text(encoding="utf-8")
        formatter_block = workflow.split("run_agent_prompt \"cursor_prompt_malware.txt\"", 1)[1]
        self.assertIn("importlib.util.spec_from_file_location", formatter_block)
        self.assertIn("trusted_malware_verdict_formatter", formatter_block)
        self.assertNotIn("sys.path.insert(0, str(_script_dir", formatter_block)
        self.assertNotIn(
            "from malware_verdict_formatter import format_malware_review_verdict",
            formatter_block,
        )

    def test_trusted_git_path_checkout_action_uses_basic_auth_fetch(self) -> None:
        self.assertTrue(_TRUSTED_GIT_CHECKOUT_ACTION.is_file())
        action = _TRUSTED_GIT_CHECKOUT_ACTION.read_text(encoding="utf-8")
        self.assertIn("never executing PR head copy", action)
        self.assertIn('http.extraheader=AUTHORIZATION: basic ${auth_basic}', action)
        self.assertIn('git checkout "FETCH_HEAD" -- "${script}"', action)
        self.assertIn("x-access-token:", action)
        self.assertNotRegex(
            action,
            r'if\s+\[\s*-f\s+"?\$?\{?script\}?"?\s*\];\s*then[\s\S]*?exit\s+0',
        )
        self.assertRegex(
            action,
            re.compile(r"Trusted file missing on origin/\$\{default_branch\}", re.MULTILINE),
        )
        self.assertNotRegex(action, r"echo\s+.*\$\{GH_TOKEN\}")


if __name__ == "__main__":
    unittest.main()
