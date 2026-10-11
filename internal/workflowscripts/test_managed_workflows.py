"""Regression tests for managed GitHub workflow templates."""

from __future__ import annotations

import os
import subprocess
import tempfile
import textwrap
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
            "Extract Dependabot comment context", 1
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
        self.assertIn("paths_manifest:", ensure_bundle)
        self.assertIn(
            ".github/scripts/dependency-cursor-review-trusted-scripts.paths",
            ensure_bundle,
        )
        self.assertIn("dest:", ensure_bundle)
        self.assertIn("trusted-dcr-scripts", ensure_bundle)
        self.assertNotIn("paths: |", ensure_bundle)
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

    def _job(self, workflow: str, name: str) -> str:
        start = workflow.index(f"\n  {name}:\n") + 1
        if name == "dependency-review":
            return workflow[start:]
        end = workflow.index(f"\n  {self._next_job(name)}:\n", start)
        return workflow[start:end]

    @staticmethod
    def _next_job(name: str) -> str:
        return {
            "dependency-review-scan": "dependency-review-agent",
            "dependency-review-agent": "dependency-review",
        }[name]

    def test_malware_formatter_imported_from_trusted_companion_not_inline(self) -> None:
        workflow = _DEPENDENCY_CURSOR_REVIEW.read_text(encoding="utf-8")
        scan = self._job(workflow, "dependency-review-scan")
        agent = self._job(workflow, "dependency-review-agent")
        verdict = self._job(workflow, "dependency-review")
        self.assertIn(
            'bash "${RUNNER_TEMP}/trusted-dcr-scripts/.github/scripts/upstream_malware_scan.sh"',
            scan,
        )
        self.assertNotIn("bash .github/scripts/upstream_malware_scan.sh", workflow)
        combine = (
            _REPO_ROOT
            / "internal"
            / "workflowscripts"
            / "dependency_cursor_review_combine_outputs.py"
        ).read_text(encoding="utf-8")
        self.assertIn("resolve_loader_bundle", combine)
        self.assertIn("runpy.run_path", combine)
        self.assertNotIn("dependency_cursor_review_trusted_loader", combine)
        self.assertNotIn("def _load_util", combine)
        self.assertNotIn("_util_via_bootstrap", combine)
        self.assertNotIn("_cold_start_module", combine)
        self.assertNotIn("_bootstrap_module_for", combine)
        self.assertIn("dependency-cursor-review-dependabot-context.js", scan)
        self.assertIn("dependency-cursor-review-target-pr.js", scan)
        self.assertIn(
            'bash "${RUNNER_TEMP}/trusted-dcr-scripts/.github/scripts/upstream_release_checkout.sh"',
            scan,
        )
        self.assertNotIn("git -C .upstream-dependency checkout --detach", workflow)
        self.assertNotIn("hash_trusted_scripts", workflow)
        self.assertNotIn("trusted_hash_snapshot", workflow)
        self.assertNotIn("cp --remove-destination", workflow)
        self.assertNotIn("frozen-malware-scan-report.json", workflow)
        self.assertNotIn("O_NOFOLLOW", combine)
        self.assertNotIn("post_comment_sha256", workflow)
        self.assertNotIn("Module.wrap", workflow)
        self.assertNotIn("/usr/bin/python3", workflow)
        self.assertNotIn("/usr/bin/sha256sum", workflow)
        self.assertNotIn("TRUSTED_DCR_SCRIPTS_SHA256", workflow)
        self.assertIn("report_sha256=", scan)
        upload = scan.split("- name: Upload scan inputs\n", 1)[1]
        for name in (
            "malware_scan_report.json",
            "malware_scan_summary.md",
            "upstream_changed_files.txt",
            "cursor_prompt_malware.txt",
            "cursor_prompt_compatibility.txt",
        ):
            self.assertIn(name, upload)
        self.assertIn("retention-days: 1", upload)
        self.assertNotIn("cursor_output_malware.json", upload)

    def test_agent_job_cannot_reach_the_verdict(self) -> None:
        """The agent runner has no write token, no verdict scripts, and no full history."""
        workflow = _DEPENDENCY_CURSOR_REVIEW.read_text(encoding="utf-8")
        scan = self._job(workflow, "dependency-review-scan")
        agent = self._job(workflow, "dependency-review-agent")
        verdict = self._job(workflow, "dependency-review")
        workflow_perms = workflow.split("\njobs:\n", 1)[0]
        self.assertIn("permissions:\n  contents: read\n", workflow_perms)
        self.assertNotIn("pull-requests:", workflow_perms)
        self.assertIn("pull-requests: read", scan)
        self.assertNotIn("pull-requests: write", scan)
        self.assertNotIn("CURSOR_API_KEY", scan)
        self.assertIn("contents: read", agent)
        self.assertNotIn("pull-requests:", agent)
        self.assertNotIn("fetch-depth: 0", agent)
        self.assertNotIn("--shallow-exclude", agent)
        self.assertNotIn("merge-base --is-ancestor", agent)
        self.assertIn('fetch --no-tags --depth=1 origin "${RESOLVED_FROM}"', agent)
        self.assertNotIn("dependency_cursor_review_combine_outputs.py", agent)
        self.assertNotIn("dependency-cursor-review-post-comment.js", agent)
        self.assertNotIn("dependency-cursor-review-dependabot-context.js", agent)
        self.assertNotIn("CURSOR_API_KEY", verdict)
        self.assertNotIn("secrets.CURSOR_API_KEY", agent.split("- name: Run Cursor agent\n", 1)[0])
        agent_step = agent.split("- name: Run Cursor agent\n", 1)[1].split("\n      - name:", 1)[0]
        self.assertIn("secrets.CURSOR_API_KEY", agent_step)
        self.assertEqual(workflow.count("secrets.CURSOR_API_KEY"), 1)
        verdict_if = verdict.split("\n    steps:\n", 1)[0]
        self.assertIn("always()", verdict_if)
        self.assertIn("!cancelled()", verdict_if)
        self.assertIn("needs.dependency-review-scan.result != 'skipped'", verdict_if)
        self.assertNotIn("already_reviewed", verdict_if)
        self.assertIn("pull-requests: write", verdict)
        self.assertIn("- name: Already reviewed", verdict)
        self.assertIn("exit 1", verdict.split("- name: Fail closed when scan or agent failed\n", 1)[1])
        post = verdict.split("- name: Post or update PR comment\n", 1)[1]
        self.assertIn(
            "require(`${process.env.GITHUB_WORKSPACE}/.github/scripts/dependency-cursor-review-post-comment.js`)",
            post,
        )
        self.assertNotIn("RUNNER_TEMP", post)
        self.assertLess(verdict.index("Checkout default-branch helpers"), verdict.index("Post or update PR comment"))
        self.assertIn("DCR_SCAN_REPORT:", verdict)
        self.assertIn("DCR_MALWARE_JSON:", verdict)
        self.assertIn("DCR_COMPAT_JSON:", verdict)
        self.assertIn("DCR_COMBINED_JSON:", verdict)
        self.assertIn("needs.dependency-review-scan.outputs.report_sha256", verdict)
        self.assertIn(
            "python3 -I .github/scripts/dependency_cursor_review_combine_outputs.py",
            verdict,
        )
        self.assertNotIn(
            "python3 -I .github/scripts/dependency_cursor_review_combine_outputs.py",
            agent,
        )
        post_js = (
            _REPO_ROOT / "internal/workflowscripts/dependency-cursor-review-post-comment.js"
        ).read_text(encoding="utf-8")
        self.assertIn("require('./dependency-cursor-review-dependabot-context.js')", post_js)
        self.assertNotIn("RUNNER_TEMP", post_js)
        self.assertIn("function selectPostedMarker", post_js)

    def test_tag_range_fetch_uses_peeled_shas(self) -> None:
        """Peeled tag SHAs and a non-ancestor pair both diff after one depth-1 fetch."""
        workflow = _DEPENDENCY_CURSOR_REVIEW.read_text(encoding="utf-8")
        agent = self._job(workflow, "dependency-review-agent")
        block = agent.split("- name: Fetch upstream from commit\n", 1)[1].split("\n      - name:", 1)[0]
        script = textwrap.dedent(block.split("run: |\n", 1)[1])
        with tempfile.TemporaryDirectory() as tmp:
            origin = Path(tmp) / "origin"
            self._git(origin, "init", "-b", "main")
            self._git_config(origin)
            for name in ("base", "released", "middle", "head"):
                (origin / "pkg.txt").write_text(name + "\n", encoding="utf-8")
                self._git(origin, "add", "pkg.txt")
                self._git(origin, "commit", "-m", name)
            self._git(origin, "tag", "-a", "v1.0.0", "-m", "v1.0.0", "HEAD~2")
            self._git(origin, "tag", "-a", "v1.2.0", "-m", "v1.2.0", "HEAD")
            resolved_from = self._git(origin, "rev-parse", "v1.0.0^{commit}")
            resolved_to = self._git(origin, "rev-parse", "v1.2.0^{commit}")
            self.assertNotEqual(resolved_from, self._git(origin, "rev-parse", "v1.0.0"))
            self._assert_tree_diff(script, origin, resolved_from, resolved_to, "-released", "+head")

            self._git(origin, "checkout", "--orphan", "rewritten")
            self._git(origin, "rm", "-rf", ".")
            (origin / "pkg.txt").write_text("orphan\n", encoding="utf-8")
            self._git(origin, "add", "pkg.txt")
            self._git(origin, "commit", "-m", "orphan")
            orphan = self._git(origin, "rev-parse", "HEAD")
            self._git(origin, "checkout", "main")
            head = self._git(origin, "rev-parse", "HEAD")
            ancestry = subprocess.run(
                ["git", "merge-base", "--is-ancestor", orphan, head],
                cwd=origin,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(ancestry.returncode, 0)
            self._assert_tree_diff(script, origin, orphan, head, "-orphan", "+head")

    def _assert_tree_diff(
        self,
        script: str,
        origin: Path,
        resolved_from: str,
        resolved_to: str,
        removed: str,
        added: str,
    ) -> None:
        work = origin.parent / f"work-{resolved_from[:8]}"
        upstream = work / ".upstream-dependency"
        self._git(upstream, "init", "-b", "main")
        self._git(upstream, "remote", "add", "origin", str(origin))
        self._git(upstream, "fetch", "--depth=1", "origin", resolved_to)
        self._git(upstream, "checkout", "--detach", "FETCH_HEAD")
        env = os.environ.copy()
        env.update(GH_TOKEN="x", RESOLVED_FROM=resolved_from)
        proc = subprocess.run(
            ["bash", "-c", script],
            cwd=work,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
        self.assertEqual(self._git(upstream, "rev-parse", "HEAD"), resolved_to)
        diff = self._git(upstream, "diff", resolved_from, resolved_to)
        self.assertIn(removed, diff)
        self.assertIn(added, diff)

    def _git(self, repo: Path, *args: str) -> str:
        repo.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(
            ["git", *args],
            cwd=repo,
            env=self._git_env(),
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, msg=f"git {args}\n{proc.stderr}")
        return proc.stdout.strip()

    def _git_config(self, repo: Path) -> None:
        self._git(repo, "config", "user.email", "range-test@example.com")
        self._git(repo, "config", "user.name", "range-test")
        self._git(repo, "config", "commit.gpgsign", "false")

    @staticmethod
    def _git_env() -> dict[str, str]:
        env = os.environ.copy()
        env.update(
            GIT_AUTHOR_NAME="range-test",
            GIT_AUTHOR_EMAIL="range-test@example.com",
            GIT_COMMITTER_NAME="range-test",
            GIT_COMMITTER_EMAIL="range-test@example.com",
        )
        return env

    def test_5dd16704_target_pr_sparse_helper_does_not_shrink_pr_checkout(self) -> None:
        """Bugbot 5dd16704: sparse helper checkout must not leave GITHUB_WORKSPACE sparse for PR head."""
        workflow = _DEPENDENCY_CURSOR_REVIEW.read_text(encoding="utf-8")
        helper_block = workflow.split("Checkout trusted target-PR helper", 1)[1].split(
            "Resolve target PR context", 1
        )[0]
        self.assertIn("path: .trusted-dcr-helper", helper_block)
        self.assertIn(
            "RUNNER_TEMP}/trusted-dcr-helper/dependency-cursor-review-target-pr.js",
            workflow,
        )
        pr_block = workflow.split("Checkout repository", 1)[1].split(
            "Install trusted git path checkout action definition", 1
        )[0]
        self.assertNotIn("sparse-checkout:", pr_block)

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
