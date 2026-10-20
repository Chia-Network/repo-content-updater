"""Regression tests for managed GitHub workflow templates."""

from __future__ import annotations

import os
import shutil
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
_SLOT = "ab" * 16
_OTHER_SLOT = "cd" * 16
_LATER_SLOT = "ef" * 16


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
            'python3 -I "${RUNNER_TEMP}/trusted-dcr-scripts/.github/scripts/dependency_update_coverage.py"',
            scan,
        )
        prompts = scan.split("- name: Build Cursor prompts\n", 1)[1].split("\n      - name:", 1)[0]
        self.assertIn("steps.malware_scan.outputs.package_name", prompts)
        self.assertIn("steps.malware_scan.outputs.from_version", prompts)
        self.assertIn("steps.malware_scan.outputs.to_version", prompts)
        self.assertNotIn("steps.dependabot_context.outputs", prompts)
        coverage = (
            _REPO_ROOT / "internal/workflowscripts/dependency_update_coverage.py"
        ).read_text(encoding="utf-8")
        self.assertIn("upstream_malware_scan.sh", coverage)
        self.assertIn("scan_conclusive", coverage)
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
        checkout_step = scan.split("- name: Check out upstream release and drop agent instructions\n", 1)[1].split(
            "\n      - name:", 1
        )[0]
        self.assertIn("steps.malware_scan.outputs.resolved_to", checkout_step)
        self.assertIn("steps.target_pr.outputs.base_sha", scan)
        checkout_sh = (
            _REPO_ROOT / "internal/workflowscripts/upstream_release_checkout.sh"
        ).read_text(encoding="utf-8")
        self.assertNotIn("agent_target", checkout_sh)
        self.assertNotIn("jq ", checkout_sh)
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
        self.assertNotIn("fetch --tags", agent)
        self.assertIn('fetch --no-tags --depth=1 origin "$sha"', agent)
        self.assertIn('refs/tags/${name}:refs/tags/${name}', agent)
        self.assertIn("refs/dcr/from", agent)
        self.assertIn("refs/dcr/to", agent)
        self.assertIn('refs/tags/${name}^{commit}', agent)
        self.assertIn('update-ref -d "refs/tags/${name}"', agent)
        self.assertEqual(agent.count("tag_name_ok()"), 1)
        self.assertNotIn("*/*/*", agent)
        self.assertIn('update-ref -d "refs/tags/${name}" || return 1', agent)
        self.assertIn('file="dcr-scan-input/cursor_prompt_compatibility.txt"', agent)
        fetch = agent.split("- name: Fetch upstream commits and version tags\n", 1)[1].split(
            "\n      - name:", 1
        )[0]
        self.assertNotIn("|| exit 1", fetch)
        self.assertNotIn("dcr-slot-[0-9a-f]", fetch)
        scan_sh = (_REPO_ROOT / "internal/workflowscripts/upstream_malware_scan.sh").read_text(encoding="utf-8")
        self.assertNotIn("tag_name_ok", scan_sh)
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
        self.assertLess(
            verdict.index("Post or update PR comment"),
            verdict.index("Fail the check on a blocking review"),
        )
        self.assertIn("--enforce-check", verdict)
        self.assertNotIn("needs.dependency-review-scan.outputs.status != 'clean'", verdict)
        self.assertIn("needs.dependency-review-scan.outputs.already_reviewed != 'true'", verdict)
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
        """Peeled commits and their version tags are inspectable after depth-1 fetches."""
        script = self._fetch_script()
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
            self._git(origin, "tag", "-a", "extra", "-m", "extra", "HEAD")
            resolved_from = self._git(origin, "rev-parse", "v1.0.0^{commit}")
            resolved_to = self._git(origin, "rev-parse", "v1.2.0^{commit}")
            self.assertNotEqual(resolved_from, self._git(origin, "rev-parse", "v1.0.0"))
            self._assert_tree_diff(
                script,
                origin,
                resolved_from,
                resolved_to,
                "-released",
                "+head",
                from_tag="v1.0.0",
                to_tag="v1.2.0",
                from_blob="released",
            )

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
            self._assert_tree_diff(
                script,
                origin,
                orphan,
                head,
                "-orphan",
                "+head",
                from_blob="orphan",
            )

    def _assert_tree_diff(
        self,
        script: str,
        origin: Path,
        resolved_from: str,
        resolved_to: str,
        removed: str,
        added: str,
        from_blob: str,
        from_tag: str = "",
        to_tag: str = "",
    ) -> None:
        work = origin.parent / f"work-{resolved_from[:8]}"
        upstream = work / ".upstream-dependency"
        self._git(upstream, "init", "-b", "main")
        self._git(upstream, "remote", "add", "origin", str(origin))
        self._git(upstream, "fetch", "--depth=1", "origin", resolved_to)
        self._git(upstream, "checkout", "--detach", "FETCH_HEAD")
        self._plant_prompts(work)
        proc = self._run_fetch(
            script,
            work,
            RESOLVED_FROM=resolved_from,
            RESOLVED_TO=resolved_to,
            FROM_TAG=from_tag,
            TO_TAG=to_tag,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
        self.assertEqual(self._git(upstream, "rev-parse", "HEAD"), resolved_to)
        self.assertEqual(self._git(upstream, "rev-parse", "refs/dcr/from"), resolved_from)
        self.assertEqual(self._git(upstream, "rev-parse", "refs/dcr/to"), resolved_to)
        diff = self._git(upstream, "diff", resolved_from, resolved_to)
        self.assertIn(removed, diff)
        self.assertIn(added, diff)
        self.assertEqual(self._git(upstream, "show", f"{resolved_from}:pkg.txt"), from_blob)
        to_blob = self._git(upstream, "show", f"{resolved_to}:pkg.txt")
        expected_tags = {tag for tag in (from_tag, to_tag) if tag}
        listed = self._git(upstream, "tag", "--list")
        self.assertEqual(set(listed.splitlines()) if listed else set(), expected_tags)
        for tag, sha, blob in (
            (from_tag, resolved_from, from_blob),
            (to_tag, resolved_to, to_blob),
        ):
            if not tag:
                continue
            self.assertEqual(self._git(upstream, "cat-file", "-t", tag), "tag")
            self.assertEqual(self._git(upstream, "rev-parse", f"{tag}^{{commit}}"), sha)
            self.assertEqual(self._git(upstream, "show", f"{tag}:pkg.txt"), blob)
        self._assert_prompt_tags(work, from_tag, to_tag)
        if from_tag:
            log = self._git(upstream, "log", "--oneline", f"{resolved_from}..{resolved_to}")
            self.assertNotIn("middle", log)
        checkout = subprocess.run(
            ["bash", str(_REPO_ROOT / "internal/workflowscripts/upstream_release_checkout.sh")],
            cwd=work,
            env={**self._git_env(), "RESOLVED_TO": resolved_to},
            capture_output=True,
            text=True,
        )
        self.assertEqual(checkout.returncode, 0, msg=checkout.stderr or checkout.stdout)
        self.assertEqual(self._git(upstream, "rev-parse", "HEAD"), resolved_to)
        self.assertEqual(self._git(upstream, "rev-parse", "refs/dcr/from"), resolved_from)
        if not from_tag:
            return
        for bad in ("not a sha", "abcdef", "a" * 65):
            refused = self._run_fetch(
                script,
                work,
                RESOLVED_FROM=bad,
                RESOLVED_TO=resolved_to,
                FROM_TAG=from_tag,
                TO_TAG=to_tag,
            )
            self.assertNotEqual(refused.returncode, 0, msg=bad)
            self.assertIn("Refusing non-SHA ref.", refused.stderr)
        for bad in ("foo@{bar", "v1..2", "-v1", ".hidden"):
            refused = self._run_fetch(
                script,
                work,
                RESOLVED_FROM=resolved_from,
                RESOLVED_TO=resolved_to,
                FROM_TAG=bad,
                TO_TAG=to_tag,
            )
            self.assertNotEqual(refused.returncode, 0, msg=bad)
            self.assertIn("Refusing tag name.", refused.stderr)
        self.assertEqual(self._git(upstream, "rev-parse", "refs/dcr/from"), resolved_from)

    def test_moved_tag_is_deleted_and_left_out_of_the_prompt(self) -> None:
        """A tag that no longer peels to the scanned commit is not shown to the agent."""
        script = self._fetch_script()
        with tempfile.TemporaryDirectory() as tmp:
            origin = Path(tmp) / "origin"
            self._git(origin, "init", "-b", "main")
            self._git_config(origin)
            (origin / "pkg.txt").write_text("released\n", encoding="utf-8")
            self._git(origin, "add", "pkg.txt")
            self._git(origin, "commit", "-m", "released")
            self._git(origin, "tag", "-a", "v1.0.0", "-m", "v1.0.0")
            self._git(origin, "tag", "-a", "moved", "-m", "moved")
            released = self._git(origin, "rev-parse", "HEAD")
            (origin / "pkg.txt").write_text("head\n", encoding="utf-8")
            self._git(origin, "add", "pkg.txt")
            self._git(origin, "commit", "-m", "head")
            self._git(origin, "tag", "-a", "v1.2.0", "-m", "v1.2.0")
            head = self._git(origin, "rev-parse", "HEAD")
            work = origin.parent / "work-moved"
            upstream = work / ".upstream-dependency"
            self._git(upstream, "init", "-b", "main")
            self._git(upstream, "remote", "add", "origin", str(origin))
            self._git(upstream, "fetch", "--depth=1", "origin", head)
            self._git(upstream, "checkout", "--detach", "FETCH_HEAD")
            self._plant_prompts(work)
            proc = self._run_fetch(
                script,
                work,
                RESOLVED_FROM=released,
                RESOLVED_TO=head,
                FROM_TAG="v1.0.0",
                TO_TAG="moved",
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
            self.assertEqual(self._git(upstream, "rev-parse", "refs/tags/v1.0.0^{commit}"), released)
            self.assertEqual(self._git(upstream, "show", "v1.0.0:pkg.txt"), "released")
            missing = subprocess.run(
                ["git", "rev-parse", "--verify", "--end-of-options", "refs/tags/moved"],
                cwd=upstream,
                env=self._git_env(),
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(missing.returncode, 0, msg=missing.stdout)
            self._assert_prompt_tags(work, "v1.0.0", "")

    def test_nested_tag_names_are_fetched(self) -> None:
        """Tag names with more than one slash are fetched when the peel matches."""
        script = self._fetch_script()
        with tempfile.TemporaryDirectory() as tmp:
            origin = Path(tmp) / "origin"
            self._git(origin, "init", "-b", "main")
            self._git_config(origin)
            for name in ("base", "released", "middle", "head"):
                (origin / "pkg.txt").write_text(name + "\n", encoding="utf-8")
                self._git(origin, "add", "pkg.txt")
                self._git(origin, "commit", "-m", name)
            self._git(origin, "tag", "-a", "rel/a/b", "-m", "rel/a/b", "HEAD~2")
            self._git(origin, "tag", "-a", "sdk/go/v1.2.3", "-m", "sdk/go/v1.2.3", "HEAD")
            resolved_from = self._git(origin, "rev-parse", "rel/a/b^{commit}")
            resolved_to = self._git(origin, "rev-parse", "sdk/go/v1.2.3^{commit}")
            self._assert_tree_diff(
                script,
                origin,
                resolved_from,
                resolved_to,
                "-released",
                "+head",
                from_blob="released",
                from_tag="rel/a/b",
                to_tag="sdk/go/v1.2.3",
            )

    def test_failed_tag_delete_stops_the_step(self) -> None:
        """A failed tag delete is a step failure and leaves that ref in place."""
        script = self._fetch_script()
        with tempfile.TemporaryDirectory() as tmp:
            origin = Path(tmp) / "origin"
            self._git(origin, "init", "-b", "main")
            self._git_config(origin)
            (origin / "pkg.txt").write_text("released\n", encoding="utf-8")
            self._git(origin, "add", "pkg.txt")
            self._git(origin, "commit", "-m", "released")
            self._git(origin, "tag", "-a", "v1.0.0", "-m", "v1.0.0")
            self._git(origin, "tag", "-a", "moved", "-m", "moved")
            released = self._git(origin, "rev-parse", "HEAD")
            (origin / "pkg.txt").write_text("head\n", encoding="utf-8")
            self._git(origin, "add", "pkg.txt")
            self._git(origin, "commit", "-m", "head")
            head = self._git(origin, "rev-parse", "HEAD")
            work = origin.parent / "work-delete"
            upstream = work / ".upstream-dependency"
            self._git(upstream, "init", "-b", "main")
            self._git(upstream, "remote", "add", "origin", str(origin))
            self._git(upstream, "fetch", "--depth=1", "origin", head)
            self._git(upstream, "checkout", "--detach", "FETCH_HEAD")
            self._plant_prompts(work)
            bin_dir = Path(tmp) / "bin"
            bin_dir.mkdir()
            real_git = shutil.which("git")
            self.assertIsNotNone(real_git)
            wrapper = bin_dir / "git"
            wrapper.write_text(
                "#!/bin/sh\n"
                'if [ "$1" = "-C" ] && [ "$3" = "update-ref" ] && [ "$4" = "-d" ]; then\n'
                "  echo 'update-ref -d failed' >&2\n"
                "  exit 1\n"
                "fi\n"
                f"exec {real_git} \"$@\"\n",
                encoding="utf-8",
            )
            wrapper.chmod(0o755)
            proc = self._run_fetch(
                script,
                work,
                RESOLVED_FROM=released,
                RESOLVED_TO=head,
                FROM_TAG="v1.0.0",
                TO_TAG="moved",
                PATH=f"{bin_dir}:{os.environ.get('PATH', '')}",
            )
            self.assertNotEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
            self.assertIn("update-ref -d failed", proc.stderr)
            self.assertEqual(self._git(upstream, "rev-parse", "refs/tags/moved^{commit}"), released)
            missing = subprocess.run(
                ["git", "rev-parse", "--verify", "--end-of-options", "refs/tags/v1.0.0"],
                cwd=upstream,
                env=self._git_env(),
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(missing.returncode, 0, msg=missing.stdout)
            for name in ("cursor_prompt_malware.txt", "cursor_prompt_compatibility.txt"):
                text = (work / "dcr-scan-input" / name).read_text(encoding="utf-8")
                self.assertIn(f"- to tag: (none) dcr-slot-{_SLOT}", text)
                self.assertNotIn("- to tag: moved", text)
                self.assertNotIn("- from tag: v1.0.0", text)

    def _fetch_script(self) -> str:
        workflow = _DEPENDENCY_CURSOR_REVIEW.read_text(encoding="utf-8")
        agent = self._job(workflow, "dependency-review-agent")
        block = agent.split("- name: Fetch upstream commits and version tags\n", 1)[1].split(
            "\n      - name:", 1
        )[0]
        return textwrap.dedent(block.split("run: |\n", 1)[1])

    def _plant_prompts(self, work: Path) -> None:
        dest = work / "dcr-scan-input"
        dest.mkdir(parents=True, exist_ok=True)
        notes = (
            "Release notes:\n"
            "- from tag: (none)\n"
            "- to tag: (none)\n"
            "- keep: yes\n"
            f"- from tag: (none) dcr-slot-{_OTHER_SLOT}\n"
            f"- to tag: (none) dcr-slot-{_OTHER_SLOT}\n"
            "\n"
            "Repository layout:\n"
            f"- from tag: (none) dcr-slot-{_SLOT}\n"
            f"- to tag: (none) dcr-slot-{_SLOT}\n"
        )
        trailing = (
            "\nMalware scan report JSON:\n"
            f"- from tag: (none) dcr-slot-{_LATER_SLOT}\n"
            f"- to tag: (none) dcr-slot-{_LATER_SLOT}\n"
        )
        (dest / "cursor_prompt_compatibility.txt").write_text(notes, encoding="utf-8")
        (dest / "cursor_prompt_malware.txt").write_text(notes + trailing, encoding="utf-8")

    def _assert_prompt_tags(self, work: Path, from_tag: str, to_tag: str) -> None:
        expected = {"from tag": from_tag, "to tag": to_tag}
        for name in ("cursor_prompt_malware.txt", "cursor_prompt_compatibility.txt"):
            lines = (work / "dcr-scan-input" / name).read_text(encoding="utf-8").splitlines()
            self.assertEqual(lines.count("- from tag: (none)"), 1)
            self.assertEqual(lines.count("- to tag: (none)"), 1)
            self.assertIn("- keep: yes", lines)
            self.assertIn(f"- from tag: (none) dcr-slot-{_OTHER_SLOT}", lines)
            self.assertIn(f"- to tag: (none) dcr-slot-{_OTHER_SLOT}", lines)
            for label, tag in expected.items():
                if tag:
                    self.assertIn(f"- {label}: {tag}", lines)
                    self.assertNotIn(f"- {label}: (none) dcr-slot-{_SLOT}", lines)
                else:
                    self.assertIn(f"- {label}: (none) dcr-slot-{_SLOT}", lines)
            if name == "cursor_prompt_malware.txt":
                self.assertIn(f"- from tag: (none) dcr-slot-{_LATER_SLOT}", lines)
                self.assertIn(f"- to tag: (none) dcr-slot-{_LATER_SLOT}", lines)

    def _run_fetch(self, script: str, work: Path, **updates: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(GH_TOKEN="x", RESOLVED_FROM="", RESOLVED_TO="", FROM_TAG="", TO_TAG="")
        env.update(updates)
        return subprocess.run(
            ["bash", "-c", script],
            cwd=work,
            env=env,
            capture_output=True,
            text=True,
        )

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
