"""Tests for the managed dependency review and Dependabot templates."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TEMPLATES = _REPO_ROOT / "templates"
_DEPENDENCY_REVIEW = _TEMPLATES / "dependency-review.yml"
_DEPENDABOT_TEMPLATES = (_TEMPLATES / "dependabot.yml", _TEMPLATES / "go-dependabot.yml")
_OSV_WORKFLOW = "google/osv-scanner-action/.github/workflows/osv-scanner-reusable-pr.yml"
_UPDATE_BLOCK = re.compile(r"^  - package-ecosystem:", re.MULTILINE)
_COOLDOWN = re.compile(r"^    cooldown:\n      default-days: 7$", re.MULTILINE)


def _job(workflow: str, name: str) -> str:
    """Return the YAML block of one job from a workflow's text."""
    marker = f"\n  {name}:\n"
    start = workflow.index(marker) + len(marker)
    next_job = re.search(r"\n  [A-Za-z0-9_-]+:\n", workflow[start:])
    return workflow[start:] if next_job is None else workflow[start : start + next_job.start()]


def _update_blocks(template: str) -> list[str]:
    """Split a Dependabot template into its per-ecosystem update blocks."""
    blocks: list[list[str]] = []
    for line in template.splitlines():
        if _UPDATE_BLOCK.match(line):
            blocks.append([line])
        elif blocks:
            blocks[-1].append(line)
    return ["\n".join(block) for block in blocks]


class DependencyReviewTemplateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = _DEPENDENCY_REVIEW.read_text(encoding="utf-8")

    def test_keeps_the_dependency_review_job_and_severity_gate(self) -> None:
        job = _job(self.workflow, "dependency-review")
        self.assertIn("uses: actions/dependency-review-action@v5.0.0", job)
        self.assertIn('fail-on-severity: "{{ .DEPENDENCY_REVIEW_FAIL_ON_SEVERITY }}"', job)

    def test_runs_osv_scanner_on_pull_request_lockfiles(self) -> None:
        job = _job(self.workflow, "osv-scanner")
        self.assertIn(f"uses: {_OSV_WORKFLOW}@v2.7.0", job)
        self.assertIn("-r\n        ./", job)
        self.assertIn("upload-sarif: false", job)

    def test_osv_scanner_job_permissions_are_read_only(self) -> None:
        job = _job(self.workflow, "osv-scanner")
        self.assertIn("permissions:\n      contents: read\n", job)
        self.assertNotRegex(job, r"(?m)^\s+[a-z-]+:\s*write\s*$")
        self.assertNotIn("pull-requests:", job)

    def test_severity_default_is_configured(self) -> None:
        config = (_REPO_ROOT / "config.yaml").read_text(encoding="utf-8")
        self.assertIn('DEPENDENCY_REVIEW_FAIL_ON_SEVERITY: "high"', config)


class DependabotCooldownTest(unittest.TestCase):
    def test_every_update_block_has_the_seven_day_cooldown(self) -> None:
        for path in _DEPENDABOT_TEMPLATES:
            with self.subTest(template=path.name):
                blocks = _update_blocks(path.read_text(encoding="utf-8"))
                self.assertGreater(len(blocks), 0)
                for block in blocks:
                    ecosystem = block.splitlines()[0].strip()
                    self.assertRegex(block, _COOLDOWN, ecosystem)


if __name__ == "__main__":
    unittest.main()
