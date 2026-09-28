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
        )[1].split("Ensure malware verdict formatter bundle", 1)[0]
        ensure_bundle = section.split("Ensure malware verdict formatter bundle", 1)[1].split(
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
        self.assertNotIn("http.extraheader=AUTHORIZATION", ensure_bundle)
        self.assertIn(
            "./.github/actions/trusted-git-path-checkout",
            ensure_bundle,
            msg="formatter bundle uses composite after trusted bootstrap",
        )
        self.assertIn(".github/scripts/malware_verdict_formatter.py", ensure_bundle)
        self.assertIn(".github/scripts/trusted_formatter_loader.py", ensure_bundle)
        self.assertIn("paths: |", ensure_bundle)
        self.assertLess(
            section.index("Install trusted git path checkout action definition"),
            section.index("Ensure malware verdict formatter bundle"),
        )

    def test_malware_formatter_imported_from_trusted_file_not_scripts_syspath(self) -> None:
        workflow = _DEPENDENCY_CURSOR_REVIEW.read_text(encoding="utf-8")
        formatter_block = workflow.split("run_agent_prompt \"cursor_prompt_malware.txt\"", 1)[1]
        self.assertIn("find_and_load_format_malware_review_verdict", formatter_block)
        self.assertIn("trusted_formatter_loader.py", formatter_block)
        self.assertNotIn("sys.path.insert(0, str(_script_dir", formatter_block)
        self.assertNotIn(
            "from malware_verdict_formatter import format_malware_review_verdict",
            formatter_block,
        )
        self.assertNotIn("import malware_verdict_formatter", formatter_block)
        self.assertNotIn("_import_module_from_trusted_script", formatter_block)
        self.assertNotIn("_exec_module_isolated_from_scripts_dir", formatter_block)
        self.assertNotIn("sys.path.insert(0,", formatter_block)
        self.assertNotIn("saved_path", formatter_block)
        self.assertIn("load_loader_module(loader_path)", formatter_block)

    def test_trusted_git_path_checkout_action_uses_basic_auth_fetch(self) -> None:
        self.assertTrue(_TRUSTED_GIT_CHECKOUT_ACTION.is_file())
        action = _TRUSTED_GIT_CHECKOUT_ACTION.read_text(encoding="utf-8")
        self.assertIn("never executing PR head copy", action)
        self.assertIn('http.extraheader=AUTHORIZATION: basic ${auth_basic}', action)
        self.assertIn('git checkout "FETCH_HEAD" -- "${checkout_targets[@]}"', action)
        self.assertIn("x-access-token:", action)
        self.assertNotRegex(
            action,
            r'if\s+\[\s*-f\s+"?\$?\{?script\}?"?\s*\];\s*then[\s\S]*?exit\s+0',
        )
