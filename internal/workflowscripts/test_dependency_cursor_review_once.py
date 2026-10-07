"""Dependabot cursor review runs once per pull request upgrade."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOW = _REPO_ROOT / "templates" / "dependency-cursor-review.yml"
_TARGET_PR = _REPO_ROOT / "internal" / "workflowscripts" / "dependency-cursor-review-target-pr.js"
_NODE_TEST = _REPO_ROOT / "internal" / "workflowscripts" / "dependency_cursor_review_once.test.js"


class DependencyCursorReviewOnceTest(unittest.TestCase):
    def test_node_once_per_upgrade_suite(self) -> None:
        proc = subprocess.run(
            ["node", "--test", str(_NODE_TEST)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)

    def test_review_job_is_gated_once_and_the_check_name_stays(self) -> None:
        workflow = _WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("pull_request_target", workflow)
        self.assertIn("types: [opened, synchronize, reopened]", workflow)
        self.assertIn("contents: read\n  pull-requests: write\n", workflow)
        self.assertNotIn("issues:", workflow)
        self.assertNotIn("Skip completed Dependabot review", workflow)
        self.assertNotIn("steps.target_pr.outputs.already_reviewed != 'true'", workflow)
        self.assertEqual(workflow.count("steps.target_pr.outputs.already_reviewed"), 1)
        self.assertIn(
            "needs.resolve-target.result == 'success' && "
            "needs.resolve-target.outputs.already_reviewed != 'true'",
            workflow,
        )
        resolve, review_and_conclusion = workflow.split("\n  resolve-target:\n", 1)[1].split(
            "\n  review:\n", 1
        )
        review, conclusion = review_and_conclusion.split("\n  dependency-review:\n", 1)
        self.assertIn("steps.target_pr.outputs.already_reviewed", resolve)
        self.assertIn("steps.target_pr.outputs.head_sha", resolve)
        self.assertIn("steps.target_pr.outputs.review_marker", resolve)
        self.assertNotIn("steps.target_pr.outputs.title", resolve)
        self.assertNotIn("steps.target_pr.outputs.body", resolve)
        self.assertIn("steps.pr_text.outputs.title", review)
        self.assertIn("steps.pr_text.outputs.body", review)
        self.assertIn("needs.resolve-target.outputs.head_sha", review)
        self.assertIn("needs.resolve-target.outputs.review_marker", review)
        self.assertNotIn("Checkout trusted target-PR helper", review)
        self.assertNotIn("needs.resolve-target.outputs.title", workflow)
        self.assertNotIn("needs.resolve-target.outputs.body", workflow)
        self.assertIn("needs.review.result", conclusion)
        self.assertIn('"failure"', conclusion)
        self.assertIn('"cancelled"', conclusion)
        self.assertIn(
            "require('./dependency-cursor-review-dependabot-context.js')",
            _TARGET_PR.read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()
