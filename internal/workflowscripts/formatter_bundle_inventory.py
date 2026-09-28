"""Authoritative formatter / DCR script inventory (bundles, stems, trusted manifest)."""

from __future__ import annotations

# Loader resolve spine (cold_start.resolve_loader_bundle markers).
LOADER_RESOLVE_MARKER_FILENAMES: tuple[str, ...] = (
    "isolated_module_exec.py",
    "script_dir_isolated_load.py",
    "trusted_formatter_loader_bootstrap.py",
    "trusted_formatter_loader.py",
)

# Co-located formatter modules preloaded beside the trusted formatter file.
FORMATTER_SIBLING_MODULE_STEMS: tuple[str, ...] = (
    "malware_verdict_patterns_regex",
    "malware_verdict_patterns_structure",
    "malware_verdict_patterns",
    "malware_verdict_policy_types",
    "malware_verdict_policy_lexical",
    "malware_verdict_policy_selection_context",
    "malware_verdict_policy_context",
    "malware_verdict_policy_rules_select",
    "malware_verdict_policy_rules_strip",
    "malware_verdict_policy_rules",
    "malware_verdict_policy_analysis",
    "malware_verdict_policy",
)

FORMATTER_RUNTIME_FILENAMES: tuple[str, ...] = (
    "formatter_bundle_inventory.py",
    "module_exec_scrub.py",
    *LOADER_RESOLVE_MARKER_FILENAMES,
    "trusted_formatter_loader_cold_start.py",
    "malware_verdict_formatter.py",
    *(f"{stem}.py" for stem in FORMATTER_SIBLING_MODULE_STEMS),
)

DCR_COMBINE_EXTRA_FILENAMES: tuple[str, ...] = (
    "dependency_cursor_review_combine_outputs.py",
)

FORMATTER_COLD_START_TEST_BUNDLE: tuple[str, ...] = FORMATTER_RUNTIME_FILENAMES

DCR_COMBINE_TEST_BUNDLE: tuple[str, ...] = (
    *FORMATTER_RUNTIME_FILENAMES,
    *DCR_COMBINE_EXTRA_FILENAMES,
)

# Consumer-repo paths for trusted-git-path-checkout (single manifest source).
TRUSTED_DCR_SCRIPT_REPO_PATHS: tuple[str, ...] = (
    ".github/scripts/dependency-cursor-review-trusted-scripts.paths",
    ".github/scripts/dependency-cursor-review-target-pr.js",
    ".github/scripts/formatter_bundle_inventory.py",
    ".github/scripts/module_exec_scrub.py",
    ".github/scripts/malware_verdict_formatter.py",
    ".github/scripts/malware_verdict_patterns.py",
    ".github/scripts/malware_verdict_patterns_regex.py",
    ".github/scripts/malware_verdict_patterns_structure.py",
    ".github/scripts/malware_verdict_policy.py",
    ".github/scripts/malware_verdict_policy_types.py",
    ".github/scripts/malware_verdict_policy_lexical.py",
    ".github/scripts/malware_verdict_policy_selection_context.py",
    ".github/scripts/malware_verdict_policy_context.py",
    ".github/scripts/malware_verdict_policy_rules.py",
    ".github/scripts/malware_verdict_policy_rules_select.py",
    ".github/scripts/malware_verdict_policy_rules_strip.py",
    ".github/scripts/malware_verdict_policy_analysis.py",
    ".github/scripts/isolated_module_exec.py",
    ".github/scripts/script_dir_isolated_load.py",
    ".github/scripts/trusted_formatter_loader.py",
    ".github/scripts/trusted_formatter_loader_bootstrap.py",
    ".github/scripts/trusted_formatter_loader_cold_start.py",
    ".github/scripts/upstream_malware_scan.sh",
    ".github/scripts/dependency_cursor_review_prompts.py",
    ".github/scripts/dependency_cursor_review_combine_outputs.py",
    ".github/scripts/dependency-cursor-review-dependabot-context.js",
    ".github/scripts/dependency-cursor-review-post-comment.js",
    ".github/scripts/upstream_malware_scan_lib.sh",
    ".github/scripts/upstream_malware_scan_findings.sh",
)
