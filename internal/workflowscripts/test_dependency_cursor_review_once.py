"""Dependabot cursor review runs once per pull request upgrade."""

from __future__ import annotations

import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOW = _REPO_ROOT / "templates" / "dependency-cursor-review.yml"
_TARGET_PR = _REPO_ROOT / "internal" / "workflowscripts" / "dependency-cursor-review-target-pr.js"
_MAKEFILE = _REPO_ROOT / "Makefile"
_GO_TEST = _REPO_ROOT / ".github" / "workflows" / "go-test.yml"
_SKIP_UNREVIEWED = "steps.target_pr.outputs.already_reviewed != 'true'"


class DependencyCursorReviewOnceTest(unittest.TestCase):
    def test_one_job_skips_after_the_trusted_helper(self) -> None:
        workflow = _WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("pull_request_target", workflow)
        self.assertIn("types: [opened, synchronize, reopened]", workflow)
        self.assertIn("contents: read\n  pull-requests: write\n", workflow)
        self.assertNotIn("issues:", workflow)
        self.assertNotIn("resolve-target:", workflow)
        self.assertNotIn("needs.resolve-target", workflow)
        self.assertEqual(workflow.count("\n  dependency-review:\n"), 1)
        self.assertIn(_SKIP_UNREVIEWED, workflow)
        self.assertIn(f"always() && {_SKIP_UNREVIEWED}", workflow)
        self.assertLess(
            workflow.index("Checkout trusted target-PR helper"),
            workflow.index("Resolve target PR context"),
        )
        self.assertLess(workflow.index("Resolve target PR context"), workflow.index("Checkout repository"))
        self.assertLess(
            workflow.index("Copy trusted helper out of the workspace"),
            workflow.index("Resolve target PR context"),
        )
        self.assertNotIn("dependabot/fetch-metadata", workflow)
        self.assertNotIn("UPDATED_DEPENDENCIES_JSON", workflow)
        self.assertNotIn("GITHUB_WORKSPACE}/.trusted-dcr-helper", workflow)
        self.assertNotIn(
            "GITHUB_WORKSPACE}/.github/scripts/dependency-cursor-review-post-comment.js",
            workflow,
        )
        helper = workflow.split("Checkout trusted target-PR helper", 1)[1].split("Resolve target PR context", 1)[0]
        self.assertIn(".github/scripts/dependency-cursor-review-post-comment.js", helper)
        self.assertIn("${RUNNER_TEMP}/trusted-dcr-helper", helper)
        self.assertIn(
            "RUNNER_TEMP}/trusted-dcr-helper/dependency-cursor-review-target-pr.js",
            workflow,
        )
        self.assertIn(
            "RUNNER_TEMP}/trusted-dcr-helper/dependency-cursor-review-post-comment.js",
            workflow,
        )
        self.assertIn("steps.target_pr.outputs.review_marker", workflow)
        self.assertIn("steps.target_pr.outputs.title", workflow)
        self.assertIn("node --test internal/workflowscripts/*.test.js", _MAKEFILE.read_text(encoding="utf-8"))
        self.assertIn("actions/setup-node@", _GO_TEST.read_text(encoding="utf-8"))
        self.assertIn("steps.target_pr.outputs.body", workflow)
        self.assertIn(
            "require('./dependency-cursor-review-dependabot-context.js')",
            _TARGET_PR.read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()
