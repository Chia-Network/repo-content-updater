"""Authoritative formatter / DCR script inventory (bundles, stems, trusted manifest)."""

from __future__ import annotations

from pathlib import Path

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
    "malware_verdict_policy_context",
    "malware_verdict_policy_rules_select",
    "malware_verdict_policy_rules_strip",
    "malware_verdict_policy_analysis",
    "malware_verdict_policy",
)

FORMATTER_RUNTIME_FILENAMES: tuple[str, ...] = (
    "formatter_bundle_inventory.py",
    "module_exec_scrub_bootstrap.py",
    "module_exec_scrub.py",
    *LOADER_RESOLVE_MARKER_FILENAMES,
    "trusted_formatter_loader_cold_start.py",
    "malware_verdict_formatter.py",
    *(f"{stem}.py" for stem in FORMATTER_SIBLING_MODULE_STEMS),
)

DCR_COMBINE_EXTRA_FILENAMES: tuple[str, ...] = (
    "dependency_cursor_review_combine_outputs.py",
)

DCR_SYNC_EXTRA_FILENAMES: tuple[str, ...] = (
    *DCR_COMBINE_EXTRA_FILENAMES,
    "dependency_cursor_review_prompts.py",
    "upstream_malware_scan.sh",
    "upstream_malware_scan_lib.sh",
    "upstream_malware_scan_findings.sh",
    "dependency-cursor-review-dependabot-context.js",
    "dependency-cursor-review-post-comment.js",
    "dependency-cursor-review-target-pr.js",
)

# Canonical workflowscripts → templates/ managed mirror (single sync authority).
SYNC_CANONICAL_TO_TEMPLATE: tuple[tuple[str, str], ...] = (
    ("malware_verdict_formatter.py", "malware-verdict-formatter.py"),
    ("malware_verdict_patterns_regex.py", "malware-verdict-patterns-regex.py"),
    ("malware_verdict_patterns_structure.py", "malware-verdict-patterns-structure.py"),
    ("malware_verdict_patterns.py", "malware-verdict-patterns.py"),
    ("malware_verdict_policy.py", "malware-verdict-policy.py"),
    ("malware_verdict_policy_types.py", "malware-verdict-policy-types.py"),
    ("malware_verdict_policy_lexical.py", "malware-verdict-policy-lexical.py"),
    ("malware_verdict_policy_context.py", "malware-verdict-policy-context.py"),
    ("malware_verdict_policy_rules_select.py", "malware-verdict-policy-rules-select.py"),
    ("malware_verdict_policy_rules_strip.py", "malware-verdict-policy-rules-strip.py"),
    ("malware_verdict_policy_analysis.py", "malware-verdict-policy-analysis.py"),
    ("module_exec_scrub_bootstrap.py", "module-exec-scrub-bootstrap.py"),
    ("module_exec_scrub.py", "module-exec-scrub.py"),
    ("formatter_bundle_inventory.py", "formatter-bundle-inventory.py"),
    ("isolated_module_exec.py", "isolated-module-exec.py"),
    ("script_dir_isolated_load.py", "script-dir-isolated-load.py"),
    ("trusted_formatter_loader.py", "trusted-formatter-loader.py"),
    (
        "trusted_formatter_loader_bootstrap.py",
        "trusted-formatter-loader-bootstrap.py",
    ),
    (
        "trusted_formatter_loader_cold_start.py",
        "trusted-formatter-loader-cold-start.py",
    ),
    ("upstream_malware_scan.sh", "upstream-malware-scan.sh"),
    (
        "dependency_cursor_review_prompts.py",
        "dependency-cursor-review-prompts.py",
    ),
    (
        "dependency_cursor_review_combine_outputs.py",
        "dependency-cursor-review-combine-outputs.py",
    ),
    ("upstream_malware_scan_lib.sh", "upstream-malware-scan-lib.sh"),
    ("upstream_malware_scan_findings.sh", "upstream-malware-scan-findings.sh"),
    (
        "dependency-cursor-review-dependabot-context.js",
        "dependency-cursor-review-dependabot-context.js",
    ),
    (
        "dependency-cursor-review-post-comment.js",
        "dependency-cursor-review-post-comment.js",
    ),
    (
        "dependency-cursor-review-target-pr.js",
        "dependency-cursor-review-target-pr.js",
    ),
)

# dependency-cursor-review group expand order (config.yaml companion_files authority).
DCR_EXPANDED_COMPANION_NAMES: tuple[str, ...] = (
    "dependency-cursor-review",
    "malware-verdict-formatter",
    "malware-verdict-patterns",
    "malware-verdict-patterns-regex",
    "malware-verdict-patterns-structure",
    "malware-verdict-policy",
    "malware-verdict-policy-types",
    "malware-verdict-policy-lexical",
    "malware-verdict-policy-context",
    "module-exec-scrub-bootstrap",
    "module-exec-scrub",
    "formatter-bundle-inventory",
    "malware-verdict-policy-rules-select",
    "malware-verdict-policy-rules-strip",
    "malware-verdict-policy-analysis",
    "isolated-module-exec",
    "script-dir-isolated-load",
    "trusted-formatter-loader",
    "trusted-formatter-loader-bootstrap",
    "trusted-formatter-loader-cold-start",
    "upstream-malware-scan",
    "dependency-cursor-review-prompts",
    "dependency-cursor-review-combine-outputs",
    "dependency-cursor-review-dependabot-context",
    "dependency-cursor-review-post-comment",
    "dependency-cursor-review-target-pr",
    "dependency-cursor-review-trusted-scripts",
    "upstream-malware-scan-lib",
    "upstream-malware-scan-findings",
    "trusted-git-path-checkout-action",
)

FORMATTER_COLD_START_TEST_BUNDLE: tuple[str, ...] = FORMATTER_RUNTIME_FILENAMES

DCR_COMBINE_TEST_BUNDLE: tuple[str, ...] = (
    *FORMATTER_RUNTIME_FILENAMES,
    *DCR_COMBINE_EXTRA_FILENAMES,
)

_TRUSTED_MANIFEST_ONLY_REPO_PATHS: tuple[str, ...] = (
    ".github/scripts/dependency-cursor-review-trusted-scripts.paths",
)

# Consumer-repo paths for trusted-git-path-checkout (single manifest source).
TRUSTED_DCR_SCRIPT_REPO_PATHS: tuple[str, ...] = (
    *_TRUSTED_MANIFEST_ONLY_REPO_PATHS,
    *(f".github/scripts/{canonical}" for canonical, _ in SYNC_CANONICAL_TO_TEMPLATE),
)


def managed_formatter_sync_pairs() -> tuple[tuple[str, str], ...]:
    """Template name, canonical filename (for formatter sync tests)."""
    return tuple((template, canonical) for canonical, template in SYNC_CANONICAL_TO_TEMPLATE)


def write_dcr_companion_golden(repo_root: Path) -> None:
    """Refresh Go test golden from DCR_EXPANDED_COMPANION_NAMES."""
    path = repo_root / "internal" / "config" / "dcr_managed_companion_names.golden"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(DCR_EXPANDED_COMPANION_NAMES) + "\n", encoding="utf-8")
