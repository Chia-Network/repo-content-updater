"""Regression tests for managed GitHub workflow templates."""

from __future__ import annotations

import re
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
            "Install Cursor CLI", 1
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

    def test_malware_formatter_imported_from_trusted_companion_not_inline(self) -> None:
        workflow = _DEPENDENCY_CURSOR_REVIEW.read_text(encoding="utf-8")
        self.assertIn("/usr/bin/python3 -I -c", workflow)
        self.assertIn('exec(compile(data, path, "exec")', workflow)
        self.assertIn('combine_b64="$(/usr/bin/base64 -w0 "$combine_path")"', workflow)
        self.assertNotIn(
            '/usr/bin/python3 -I "${RUNNER_TEMP}/trusted-dcr-scripts/.github/scripts/dependency_cursor_review_combine_outputs.py"',
            workflow,
        )
        self.assertIn(
            'bash "${RUNNER_TEMP}/trusted-dcr-scripts/.github/scripts/upstream_malware_scan.sh"',
            workflow,
        )
        self.assertNotIn("python3 -I .github/scripts/", workflow)
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
        self.assertIn("dependency-cursor-review-dependabot-context.js", workflow)
        self.assertIn("dependency-cursor-review-target-pr.js", workflow)
        self.assertIn(
            'bash "${RUNNER_TEMP}/trusted-dcr-scripts/.github/scripts/upstream_release_checkout.sh"',
            workflow,
        )
        self.assertNotIn("git -C .upstream-dependency checkout --detach", workflow)
        self.assertIn("hash_trusted_scripts", workflow)
        self.assertIn("trusted_hash_snapshot", workflow)
        self.assertIn("Trusted review scripts changed before combine.", workflow)
        self.assertIn("cp --remove-destination", workflow)
        self.assertIn("${RUNNER_TEMP}/frozen-malware-scan-report.json", workflow)
        self.assertIn("report_sha256=", workflow)
        self.assertIn("/usr/bin/sha256sum", workflow)
        self.assertNotIn("TRUSTED_DCR_SCRIPTS_SHA256", workflow)
        self.assertNotIn(
            'cp malware_scan_report.json "${trusted_root}/malware_scan_report.json"',
            workflow,
        )
        self.assertIn("/usr/bin/rm -f malware_scan_report.json", workflow)
        self.assertLess(
            workflow.index("dependency_cursor_review_prompts.py"),
            workflow.index("/usr/bin/rm -f malware_scan_report.json"),
        )
        self.assertLess(
            workflow.index("/usr/bin/rm -f malware_scan_report.json"),
            workflow.index('run_agent_prompt "cursor_prompt_malware.txt"'),
        )
        self.assertLess(
            workflow.index("trusted_hash_snapshot="),
            workflow.index('run_agent_prompt "cursor_prompt_malware.txt"'),
        )
        self.assertLess(
            workflow.index('run_agent_prompt "cursor_prompt_compatibility.txt"'),
            workflow.index('if [ "$trusted_hash_now" != "$trusted_hash_snapshot" ]'),
        )
        self.assertIn(
            '/usr/bin/find "$trusted_root" -type f -print0 | LC_ALL=C /usr/bin/sort -z | /usr/bin/xargs -0 -r /usr/bin/sha256sum',
            workflow,
        )
        self.assertIn(
            'seal_digest "${dest}/dependency-cursor-review-post-comment.js" post_comment_sha256',
            workflow,
        )
        self.assertIn(
            'seal_digest "${dest}/dependency-cursor-review-dependabot-context.js" post_comment_context_sha256',
            workflow,
        )
        self.assertIn("steps.trusted_helper.outputs.post_comment_sha256", workflow)
        self.assertIn("steps.trusted_helper.outputs.post_comment_context_sha256", workflow)
        self.assertLess(
            workflow.index("post_comment_sha256"),
            workflow.index("- name: Run Cursor analysis"),
        )
        self.assertLess(
            workflow.index("post_comment_context_sha256"),
            workflow.index("- name: Run Cursor analysis"),
        )
        analysis = workflow.split("- name: Run Cursor analysis\n", 1)[1].split("\n      - name:", 1)[0]
        self.assertNotIn("GITHUB_OUTPUT", analysis)
        self.assertNotIn("post_comment_sha256", analysis)
        self.assertNotIn("post_comment_context_sha256", analysis)
        self.assertIn("/usr/bin/sha256sum -c -", workflow)
        self.assertIn("Module.wrap", workflow)
        self.assertNotIn(
            "require(`${process.env.RUNNER_TEMP}/trusted-dcr-helper/dependency-cursor-review-post-comment.js`)",
            workflow,
        )
        upload = workflow.split("- name: Upload malware scan artifacts\n", 1)[1].split("\n      - name:", 1)[0]
        self.assertIn("frozen-malware-scan-report.json", upload)
        self.assertNotIn("upstream_changed_files.txt", upload)
        self.assertLess(
            workflow.index("/usr/bin/sha256sum -c -"),
            workflow.index("actions/upload-artifact@v7"),
        )

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
