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
        self.assertIn(
            ".github/scripts/trusted_formatter_loader_bootstrap.py", ensure_bundle
        )
        self.assertIn(".github/scripts/upstream_malware_scan.sh", ensure_bundle)
        self.assertIn(
            ".github/scripts/dependency_cursor_review_combine_outputs.py", ensure_bundle
        )
        self.assertIn("paths: |", ensure_bundle)
        self.assertLess(
            section.index("Install trusted git path checkout action definition"),
            section.index("Ensure malware verdict formatter bundle"),
        )

    def test_dependency_cursor_review_workflow_under_line_budget(self) -> None:
        line_count = len(
            _DEPENDENCY_CURSOR_REVIEW.read_text(encoding="utf-8").splitlines()
        )
        self.assertLess(
            line_count,
            1000,
            msg="dependency-cursor-review.yml should stay under thermonuclear line budget",
        )

    def test_malware_formatter_imported_from_trusted_companion_not_inline(self) -> None:
        workflow = _DEPENDENCY_CURSOR_REVIEW.read_text(encoding="utf-8")
        self.assertIn(
            "python3 .github/scripts/dependency_cursor_review_combine_outputs.py",
            workflow,
        )
        self.assertIn("bash .github/scripts/upstream_malware_scan.sh", workflow)
        combine = (
            _REPO_ROOT
            / "internal"
            / "workflowscripts"
            / "dependency_cursor_review_combine_outputs.py"
        ).read_text(encoding="utf-8")
        trusted_loader = (
            _REPO_ROOT
            / "internal"
            / "workflowscripts"
            / "dependency_cursor_review_trusted_loader.py"
        ).read_text(encoding="utf-8")
        self.assertIn("dependency_cursor_review_trusted_loader", combine)
        self.assertIn("resolve_trusted_formatter_loader_module", trusted_loader)
        self.assertNotIn("_bootstrap_module_for", combine)
        self.assertNotIn("_exec_module_isolated", combine)
        self.assertIn("dependency-cursor-review-dependabot-context.js", workflow)

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
