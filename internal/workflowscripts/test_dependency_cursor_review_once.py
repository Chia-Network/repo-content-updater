"""Dependabot cursor review runs once per pull request upgrade."""

from __future__ import annotations

import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOW = _REPO_ROOT / "templates" / "dependency-cursor-review.yml"
_TARGET_PR = _REPO_ROOT / "internal" / "workflowscripts" / "dependency-cursor-review-target-pr.js"
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
        metadata = workflow.split("Fetch Dependabot metadata", 1)[1].split("Resolve target PR context", 1)[0]
        self.assertLess(workflow.index("Fetch Dependabot metadata"), workflow.index("Resolve target PR context"))
        self.assertIn("uses: dependabot/fetch-metadata@v3", metadata)
        self.assertIn("continue-on-error: true", metadata)
        self.assertIn(
            "github.event_name == 'pull_request' && github.event.pull_request.user.login == 'dependabot[bot]'",
            metadata,
        )
        self.assertNotIn("skip-verification", metadata)
        self.assertNotIn("alert-lookup", metadata)
        self.assertNotIn("github-token", metadata)
        self.assertIn("steps.dependabot_metadata.outputs.updated-dependencies-json", workflow)
        self.assertIn("steps.target_pr.outputs.title", workflow)
        self.assertIn("steps.target_pr.outputs.body", workflow)
        self.assertIn(
            "require('./dependency-cursor-review-dependabot-context.js')",
            _TARGET_PR.read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()
