"""Tests for the opt-in dependency artifact review workflow template."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

_TEMPLATE = Path(__file__).resolve().parents[2] / "templates" / "dependency-artifact-review.yml"


def _job(workflow: str, name: str) -> str:
    match = re.search(rf"^  {re.escape(name)}:\n", workflow, re.MULTILINE)
    if match is None:
        raise AssertionError(f"missing job {name}")
    following = re.search(r"^  [A-Za-z0-9_-]+:\n", workflow[match.end() :], re.MULTILINE)
    return workflow[match.end() : match.end() + following.start()] if following else workflow[match.end() :]


def _step(job: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    start = job.index(marker) + len(marker)
    following = job.find("\n      - name:", start)
    return job[start:] if following < 0 else job[start:following]


class ArtifactReviewTemplateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = _TEMPLATE.read_text(encoding="utf-8")
        self.review = _job(self.workflow, "review")
        self.publish = _job(self.workflow, "dependency-artifact-review")

    def test_trusted_scripts_come_from_the_default_branch(self) -> None:
        for job in (self.review, self.publish):
            self.assertIn("ref: ${{`{{ github.event.repository.default_branch }}`}}", job)
        self.assertIn("python3 -I .trusted-dcr-scripts/.github/scripts/dcr_fetch.py", self.workflow)
        self.assertIn("python3 -I .trusted-dcr-scripts/.github/scripts/dcr_verdict.py", self.workflow)

    def test_no_step_checks_out_or_runs_the_pr_head(self) -> None:
        self.assertNotIn("head.ref", self.workflow)
        self.assertNotIn("head_ref", self.workflow)
        self.assertNotIn("ref: ${{`{{ github.event.pull_request", self.workflow)

    def test_agent_step_blanks_the_tokens(self) -> None:
        agent = _step(self.review, "Run Cursor agent")
        for token in (
            'GITHUB_TOKEN: ""',
            'GH_TOKEN: ""',
            'ACTIONS_CACHE_URL: ""',
            'ACTIONS_RESULTS_URL: ""',
            'ACTIONS_RUNTIME_TOKEN: ""',
        ):
            self.assertIn(token, agent)

    def test_agent_steps_are_gated_on_the_reviewable_output(self) -> None:
        for name in ("Install Cursor CLI", "Run Cursor agent"):
            step = _step(self.review, name)
            self.assertIn("if: steps.fetch.outputs.reviewable == 'true'", step)

    def test_job_permissions(self) -> None:
        self.assertRegex(self.review, r"(?m)^    permissions:\n      contents: read\n      pull-requests: read\n")
        self.assertRegex(self.publish, r"(?m)^    permissions:\n      contents: read\n      pull-requests: write\n")

    def test_final_step_fails_unless_the_result_is_success(self) -> None:
        final = _step(self.publish, "Set the check result")
        self.assertIn("steps.verdict.outputs.conclusion != 'success'", final)
        self.assertIn("exit 1", final)


if __name__ == "__main__":
    unittest.main()
