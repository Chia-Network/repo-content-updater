"""Dependabot cursor review runs once per pull request upgrade."""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOW = _REPO_ROOT / "templates" / "dependency-cursor-review.yml"
_TARGET_PR = _REPO_ROOT / "internal" / "workflowscripts" / "dependency-cursor-review-target-pr.js"
_NODE_TEST = _REPO_ROOT / "internal" / "workflowscripts" / "dependency_cursor_review_once.test.js"
_REVIEW_GUARD = "steps.target_pr.outputs.already_reviewed != 'true'"


def _step_blocks(workflow: str) -> list[tuple[str, str]]:
    parts = re.split(r"\n      - name: ", workflow)
    blocks: list[tuple[str, str]] = []
    for part in parts[1:]:
        name, _, body = part.partition("\n")
        blocks.append((name.strip(), body))
    return blocks


class DependencyCursorReviewOnceTest(unittest.TestCase):
    def test_node_once_per_upgrade_suite(self) -> None:
        proc = subprocess.run(
            ["node", "--test", str(_NODE_TEST)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)

    def test_workflow_skips_only_after_the_trusted_helper_runs(self) -> None:
        workflow = _WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("pull_request_target", workflow)
        self.assertIn("types: [opened, synchronize, reopened]", workflow)
        self.assertIn("contents: read\n  pull-requests: write\n", workflow)
        self.assertNotIn("issues:", workflow)
        job_if = workflow.split("jobs:", 1)[1].split("runs-on:", 1)[0]
        self.assertIn("dependabot[bot]", job_if)
        self.assertIn("renovate[bot]", job_if)
        self.assertNotIn("already_reviewed", job_if)
        helper = workflow.split("Checkout trusted target-PR helper", 1)[1].split(
            "Resolve target PR context", 1
        )[0]
        self.assertIn("dependency-cursor-review-target-pr.js", helper)
        self.assertIn("dependency-cursor-review-dependabot-context.js", helper)
        self.assertIn(
            ".trusted-dcr-helper/.github/scripts/dependency-cursor-review-target-pr.js",
            workflow,
        )
        self.assertIn(
            "require('./dependency-cursor-review-dependabot-context.js')",
            _TARGET_PR.read_text(encoding="utf-8"),
        )
        self.assertLess(
            workflow.index("Resolve target PR context"),
            workflow.index("Checkout repository"),
        )
        post = workflow.split("Post or update PR comment", 1)[1].split("script: |", 1)[0]
        self.assertIn("UPGRADE_IDENTITY:", post)
        self.assertIn(_REVIEW_GUARD, post)

    def test_every_review_step_is_gated_on_the_prior_review_output(self) -> None:
        workflow = _WORKFLOW.read_text(encoding="utf-8")
        blocks = _step_blocks(workflow)
        self.assertGreaterEqual(len(blocks), 4)
        self.assertEqual(blocks[0][0], "Checkout trusted target-PR helper")
        self.assertEqual(blocks[1][0], "Resolve target PR context")
        self.assertNotIn("already_reviewed", blocks[0][1])
        self.assertNotIn("already_reviewed", blocks[1][1])
        self.assertEqual(blocks[2][0], "Skip completed Dependabot review")
        self.assertIn("steps.target_pr.outputs.already_reviewed == 'true'", blocks[2][1])
        for name, body in blocks[3:]:
            self.assertIn(_REVIEW_GUARD, body, msg=name)
            if name == "Upload malware scan artifacts":
                self.assertIn("always()", body)
            else:
                self.assertIn("success()", body, msg=name)


if __name__ == "__main__":
    unittest.main()
