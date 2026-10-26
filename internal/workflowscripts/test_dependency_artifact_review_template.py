"""Tests for the opt-in dependency artifact review workflow template."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TEMPLATE = _REPO_ROOT / "templates" / "dependency-artifact-review.yml"
_CONFIG = _REPO_ROOT / "config.yaml"
_README = _REPO_ROOT / "readme.md"

_EXPECTED_PINS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1 # v7",
    "actions/upload-artifact": "cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7",
    "actions/download-artifact": "9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8",
    "actions/github-script": "3a2844b7e9c422d3c10d287c895573f7108da1b3 # v9",
    "dependabot/fetch-metadata": "21025c705c08248db411dc16f3619e6b5f9ea21a # v2",
    "actions/setup-python": "6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0",
}
_USES = re.compile(r"^\s+uses:\s+(\S+)(?:\s+(#\s*\S+))?$", re.MULTILINE)
_JOB_HEADER = re.compile(r"^  ([A-Za-z0-9_-]+):$", re.MULTILINE)


def _job(workflow: str, name: str) -> str:
    """Return the top-level job block named ``name``."""
    match = re.search(rf"^  {re.escape(name)}:\n", workflow, re.MULTILINE)
    if match is None:
        raise AssertionError(f"missing job {name}")
    start = match.end()
    following = _JOB_HEADER.search(workflow, start)
    return workflow[start:] if following is None else workflow[start : following.start()]


def _step(job: str, name: str) -> str:
    """Return the step block named ``name`` from a job block."""
    marker = f"      - name: {name}\n"
    start = job.index(marker) + len(marker)
    following = job.find("\n      - name:", start)
    return job[start:] if following < 0 else job[start:following]


class ArtifactReviewTemplateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = _TEMPLATE.read_text(encoding="utf-8")
        self.prepare = _job(self.workflow, "prepare")
        self.agent = _job(self.workflow, "agent")
        self.publish = _job(self.workflow, "dependency-artifact-review")

    def test_publish_job_has_a_unique_check_name(self) -> None:
        self.assertRegex(self.workflow, r"(?m)^  dependency-artifact-review:$")
        self.assertNotRegex(self.workflow, r"(?m)^  dependency-review:$")
        readme = _README.read_text(encoding="utf-8")
        self.assertIn("publish job id is `dependency-artifact-review`", readme)
        self.assertIn("Dependency Artifact Review / dependency-artifact-review", readme)

    def test_every_action_is_pinned_with_a_version_comment(self) -> None:
        uses = _USES.findall(self.workflow)
        self.assertTrue(uses)
        for reference, comment in uses:
            name, _, ref = reference.partition("@")
            self.assertRegex(ref, r"^[0-9a-f]{40}$", reference)
            self.assertRegex(comment, r"^# v[0-9]", reference)
            self.assertIn(name, _EXPECTED_PINS, reference)
            self.assertEqual(f"{name}@{_EXPECTED_PINS[name]}", f"{name}@{ref} {comment}", reference)

    def test_cursor_cli_comes_from_the_pinned_tarball(self) -> None:
        install = _step(self.agent, "Install Cursor CLI")
        self.assertNotIn("cursor.com/install", self.workflow)
        self.assertNotRegex(self.workflow, r"curl[^\n]*\|\s*(?:bash|sh)\b")
        self.assertIn(
            "https://downloads.cursor.com/lab/${CURSOR_CLI_VERSION}/linux/x64/agent-cli-package.tar.gz",
            install,
        )
        self.assertIn("sha256sum -c -", install)
        self.assertIn("tar --strip-components=1 -xzf", install)
        self.assertIn('ln -s "$install_dir/cursor-agent" "$install_dir/agent"', install)
        self.assertIn('CURSOR_CLI_VERSION: "{{ .CURSOR_CLI_VERSION }}"', install)
        self.assertIn('CURSOR_CLI_SHA256: "{{ .CURSOR_CLI_SHA256 }}"', install)

    def test_agent_runs_only_when_the_fetch_is_reviewable(self) -> None:
        self.assertIn("id: fetch", self.prepare)
        self.assertIn("reviewable: ${{`{{ steps.fetch.outputs.reviewable }}`}}", self.prepare)
        self.assertIn("if: ${{`{{ needs.prepare.outputs.reviewable == 'true' }}`}}", self.agent)

    def test_failure_still_runs_the_verdict_and_posts_the_comment(self) -> None:
        self.assertNotIn("Fail closed when prepare or agent failed", self.publish)
        for name in (
            "Checkout trusted verdict script",
            "Set up Python",
            "Download verdict inputs",
            "Decide and compose comment",
            "Post or update PR comment",
            "Set the check result",
        ):
            with self.subTest(step=name):
                self.assertIn("if: ${{`{{ always()", _step(self.publish, name))
        self.assertIn("continue-on-error: true", _step(self.publish, "Download verdict inputs"))
        self.assertIn(
            "steps.verdict.outputs.conclusion != 'success'",
            _step(self.publish, "Set the check result"),
        )

    def test_publish_downloads_only_the_small_verdict_inputs(self) -> None:
        inputs = _step(self.prepare, "Upload review inputs")
        self.assertIn("name: dcr-review-input-${{`{{ github.run_id }}`}}", inputs)
        metadata = _step(self.prepare, "Upload review metadata")
        self.assertIn("name: dcr-verdict-meta-${{`{{ github.run_id }}`}}", metadata)
        self.assertTrue(metadata.rstrip().endswith("meta.json"))
        output = _step(self.agent, "Upload agent output")
        self.assertIn("name: dcr-verdict-agent-${{`{{ github.run_id }}`}}", output)
        self.assertTrue(output.rstrip().endswith("agent_output.txt"))
        download = _step(self.publish, "Download verdict inputs")
        self.assertIn("pattern: dcr-verdict-*", download)
        self.assertNotIn("dcr-review-input", self.publish)

    def test_comment_lookup_only_uses_the_actions_bot(self) -> None:
        post = _step(self.publish, "Post or update PR comment")
        self.assertIn("comment.user?.type === 'Bot'", post)
        self.assertIn("comment.user?.login === 'github-actions[bot]'", post)

    def test_result_fallback_uses_the_last_non_empty_assistant_text(self) -> None:
        agent_run = _step(self.agent, "Run Cursor agent")
        self.assertRegex(agent_run, r'map\(select\(length > 0\)\)\s*\|\s*last // ""')

    def test_fetch_receives_the_pull_request_head_ref(self) -> None:
        fetch = _step(self.prepare, "Fetch published artifacts")
        self.assertIn(
            "DCR_HEAD_REF: ${{`{{ github.event.pull_request.head.ref || steps.pr.outputs.head_ref }}`}}",
            fetch,
        )


class ArtifactReviewConfigTest(unittest.TestCase):
    def test_cursor_cli_version_and_digest_are_configured(self) -> None:
        config = _CONFIG.read_text(encoding="utf-8")
        self.assertIn('CURSOR_CLI_VERSION: "2026.10.22-27dcf5f"', config)
        self.assertIn(
            'CURSOR_CLI_SHA256: "85296944e4600a83c4b764f578d1502bf9c416db200d33a593e8f3ecabfdc294"',
            config,
        )

    def test_readme_notes_that_dep_review_is_adopt_only(self) -> None:
        readme = _README.read_text(encoding="utf-8")
        self.assertIn("It is adopt-only", readme)
        self.assertIn("lacks the adoption marker", readme)
        self.assertIn("unless it lists `dep-review` explicitly", readme)


if __name__ == "__main__":
    unittest.main()
