"""Dependabot cursor review runs once per pull request upgrade."""

from __future__ import annotations

import itertools
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOW = _REPO_ROOT / "templates" / "dependency-cursor-review.yml"
_TARGET_PR = _REPO_ROOT / "internal" / "workflowscripts" / "dependency-cursor-review-target-pr.js"
_MAKEFILE = _REPO_ROOT / "Makefile"
_GO_TEST = _REPO_ROOT / ".github" / "workflows" / "go-test.yml"


class DependencyCursorReviewOnceTest(unittest.TestCase):
    def test_one_job_skips_after_the_trusted_helper(self) -> None:
        workflow = _WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("pull_request_target", workflow)
        self.assertIn("types: [opened, synchronize, reopened]", workflow)
        self.assertIn("permissions:\n  contents: read\n", workflow)
        self.assertIn("pull-requests: write\n", workflow)
        self.assertNotIn("issues:", workflow)
        self.assertNotIn("resolve-target:", workflow)
        self.assertNotIn("needs.resolve-target", workflow)
        self.assertEqual(workflow.count("\n  dependency-review:\n"), 1)
        self.assertNotIn("steps.target_pr.outputs.already_reviewed", workflow)
        steps = (
            "Checkout trusted review scripts",
            "Copy trusted scripts out of the workspace",
            "Resolve target PR context",
            "Checkout repository",
        )
        for earlier, later in itertools.pairwise(steps):
            self.assertLess(workflow.index(earlier), workflow.index(later))
        self.assertNotIn("dependabot/fetch-metadata", workflow)
        self.assertNotIn("UPDATED_DEPENDENCIES_JSON", workflow)
        trusted = workflow.split("- name: Checkout trusted review scripts\n", 1)[1].split("\n      - name:", 1)[0]
        self.assertIn("ref: ${{`{{ github.event.repository.default_branch }}`}}", trusted)
        self.assertIn("sparse-checkout: |\n            .github/scripts/\n", trusted)
        self.assertIn(
            "RUNNER_TEMP}/trusted-dcr-scripts/dependency-cursor-review-target-pr.js",
            workflow,
        )
        self.assertIn(
            "GITHUB_WORKSPACE}/.github/scripts/dependency-cursor-review-post-comment.js",
            workflow,
        )
        self.assertIn("steps.bind_review.outputs.review_marker", workflow)
        self.assertIn("steps.bind_review.outputs.already_reviewed", workflow)
        self.assertIn("steps.target_pr.outputs.patch_id", workflow)
        self.assertIn("steps.target_pr.outputs.reviewed_shas", workflow)
        self.assertNotIn("VERSION_RANGE_FROM_BODY", workflow)
        self.assertNotIn("MALWARE_SCAN_STATUS", workflow)
        self.assertIn("steps.target_pr.outputs.title", workflow)
        self.assertIn(
            "node --test internal/workflowscripts/*.test.js",
            _MAKEFILE.read_text(encoding="utf-8"),
        )
        self.assertIn("actions/setup-node@", _GO_TEST.read_text(encoding="utf-8"))
        self.assertIn("steps.target_pr.outputs.body", workflow)
        self.assertIn(
            "require('./dependency-cursor-review-dependabot-context.js')",
            _TARGET_PR.read_text(encoding="utf-8"),
        )

    def test_post_step_requires_successful_analysis(self) -> None:
        workflow = _WORKFLOW.read_text(encoding="utf-8")
        agent = workflow.split("\n  dependency-review-agent:\n", 1)[1].split("\n  dependency-review:\n", 1)[0]
        verdict = workflow.split("\n  dependency-review:\n", 1)[1]
        gate = (
            "needs.dependency-review-scan.result == 'success' && "
            "needs.dependency-review-scan.outputs.already_reviewed != 'true' && "
            "needs.dependency-review-agent.result == 'success'"
        )
        self.assertEqual(verdict.count(gate), 1)
        post = verdict.split("- name: Post or update PR comment\n", 1)[1]
        self.assertIn("- name: Run Cursor agent\n", agent)
        self.assertIn("steps.helpers.outcome == 'success'", post)
        self.assertNotIn(gate, post)
        self.assertNotIn("dependency-cursor-review-post-comment.js", agent)
        self.assertNotIn("dependency-cursor-review-dependabot-context.js", agent)
        fail_check = verdict.split("- name: Fail the check on a blocking review\n", 1)
        self.assertEqual(len(fail_check), 2)
        self.assertLess(
            verdict.index("Post or update PR comment"),
            verdict.index("Fail the check on a blocking review"),
        )
        self.assertIn("--enforce-check", fail_check[1])
        self.assertNotIn("status != 'clean'", fail_check[1])
        self.assertNotIn("already_reviewed", fail_check[1])
        self.assertIn("exit 1", fail_check[1])
        self.assertNotIn("warn_only", fail_check[1])
        self.assertNotIn("MALWARE_WARN_ONLY", fail_check[1])
        scan_sh = (_REPO_ROOT / "internal/workflowscripts/upstream_malware_scan.sh").read_text(encoding="utf-8")
        self.assertNotIn("\n  exit 1\n", scan_sh)


if __name__ == "__main__":
    unittest.main()
