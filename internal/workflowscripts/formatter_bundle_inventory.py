"""Repo-authoring inventory (sync + manifest generation; not consumer runtime)."""

from __future__ import annotations

import re
from pathlib import Path

from formatter_runtime_bundle import (
    FORMATTER_RUNTIME_FILENAMES,
    FORMATTER_SIBLING_MODULE_STEMS,
    LOADER_RESOLVE_MARKER_FILENAMES,
)

_DCR_WORKFLOW = "dependency-cursor-review"
_MANAGED_FILE_PATH = re.compile(
    r"- name: ([^\n]+)\n(?:.*\n)*?    repo_path: ([^\n]+)",
    re.MULTILINE,
)
_DCR_COMPANION_BLOCK = re.compile(
    rf"- name: {_DCR_WORKFLOW}\n(?:.*\n)*?    companion_files:\n((?:      - .+\n)+)",
    re.MULTILINE,
)
_DCR_GROUP_TEMPLATES = re.compile(
    rf"- name: {_DCR_WORKFLOW}\n(?:.*\n)*?    templates:\n((?:      - .+\n)+)",
    re.MULTILINE,
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

# Consumer checkout / templates sync (formatter_runtime_bundle is runtime authority).
CONSUMER_SYNC_CANONICAL_TO_TEMPLATE: tuple[tuple[str, str], ...] = (
    ("malware_verdict_formatter.py", "malware-verdict-formatter.py"),
    ("malware_verdict_patterns_regex.py", "malware-verdict-patterns-regex.py"),
    ("malware_verdict_patterns_structure.py", "malware-verdict-patterns-structure.py"),
    ("malware_verdict_patterns.py", "malware-verdict-patterns.py"),
    ("malware_verdict_policy.py", "malware-verdict-policy.py"),
    ("malware_verdict_policy_types.py", "malware-verdict-policy-types.py"),
    ("malware_verdict_policy_lexical.py", "malware-verdict-policy-lexical.py"),
    ("malware_verdict_policy_context.py", "malware-verdict-policy-context.py"),
    ("malware_verdict_policy_strip_eligibility.py", "malware-verdict-policy-strip-eligibility.py"),
    ("malware_verdict_policy_rules_select.py", "malware-verdict-policy-rules-select.py"),
    ("malware_verdict_policy_rules_strip.py", "malware-verdict-policy-rules-strip.py"),
    ("malware_verdict_policy_analysis.py", "malware-verdict-policy-analysis.py"),
    ("scripts_dir_module_loader.py", "scripts-dir-module-loader.py"),
    ("module_exec_scrub_bootstrap.py", "module-exec-scrub-bootstrap.py"),
    ("module_exec_scrub.py", "module-exec-scrub.py"),
    ("formatter_runtime_bundle.py", "formatter-runtime-bundle.py"),
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

# Repo-content-updater authoring mirror only (not consumer trusted checkout).
AUTHORING_ONLY_SYNC_CANONICAL_TO_TEMPLATE: tuple[tuple[str, str], ...] = (
    ("formatter_bundle_inventory.py", "formatter-bundle-inventory.py"),
)

SYNC_CANONICAL_TO_TEMPLATE: tuple[tuple[str, str], ...] = (
    *CONSUMER_SYNC_CANONICAL_TO_TEMPLATE,
    *AUTHORING_ONLY_SYNC_CANONICAL_TO_TEMPLATE,
)

FORMATTER_COLD_START_TEST_BUNDLE: tuple[str, ...] = FORMATTER_RUNTIME_FILENAMES

DCR_COMBINE_TEST_BUNDLE: tuple[str, ...] = (
    *FORMATTER_RUNTIME_FILENAMES,
    *DCR_COMBINE_EXTRA_FILENAMES,
)

_TRUSTED_MANIFEST_ONLY_REPO_PATHS: tuple[str, ...] = (
    ".github/scripts/dependency-cursor-review-trusted-scripts.paths",
)


def _parse_yaml_name_list(block: str) -> tuple[str, ...]:
    return tuple(
        line.strip().removeprefix("- ").strip()
        for line in block.splitlines()
        if line.strip()
    )


def parse_dcr_companion_files(config_text: str) -> tuple[str, ...]:
    """Ordered companion_files from config.yaml (files.dependency-cursor-review)."""
    block = _DCR_COMPANION_BLOCK.search(config_text)
    if block is None:
        raise ValueError(f"missing {_DCR_WORKFLOW} companion_files in config.yaml")
    return _parse_yaml_name_list(block.group(1))


def parse_dcr_expanded_managed_names(config_text: str) -> tuple[str, ...]:
    """ExpandManagedFileEntries order: workflow + companion_files."""
    return (_DCR_WORKFLOW, *parse_dcr_companion_files(config_text))


def parse_dcr_group_templates(config_text: str) -> tuple[str, ...]:
    block = _DCR_GROUP_TEMPLATES.search(config_text)
    if block is None:
        raise ValueError(f"missing group {_DCR_WORKFLOW} templates in config.yaml")
    return _parse_yaml_name_list(block.group(1))


def trusted_dcr_script_repo_paths(config_text: str) -> tuple[str, ...]:
    """Consumer trusted-git-path-checkout manifest (.github/scripts/* only)."""
    companion_names = parse_dcr_companion_files(config_text)
    name_to_path = {
        name: path.strip()
        for name, path in _MANAGED_FILE_PATH.findall(config_text)
    }
    ordered: list[str] = [*_TRUSTED_MANIFEST_ONLY_REPO_PATHS]
    for name in companion_names:
        path = name_to_path.get(name)
        if path and path.startswith(".github/scripts/"):
            ordered.append(path)
    return tuple(ordered)


def managed_formatter_sync_pairs() -> tuple[tuple[str, str], ...]:
    """Template name, canonical filename (consumer sync face)."""
    return tuple(
        (template, canonical)
        for canonical, template in CONSUMER_SYNC_CANONICAL_TO_TEMPLATE
    )


def write_dcr_companion_golden(repo_root: Path) -> None:
    config_text = (repo_root / "config.yaml").read_text(encoding="utf-8")
    names = parse_dcr_expanded_managed_names(config_text)
    path = repo_root / "internal" / "config" / "dcr_managed_companion_names.golden"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(names) + "\n", encoding="utf-8")


def validate_config_companion_ordering(config_text: str) -> None:
    companions = parse_dcr_companion_files(config_text)
    group_templates = parse_dcr_group_templates(config_text)
    expected_group = (_DCR_WORKFLOW, *companions)
    if group_templates != expected_group:
        raise ValueError(
            "groups.dependency-cursor-review.templates must equal "
            "[dependency-cursor-review] + files.companion_files"
        )
    synced = {canonical for canonical, _ in CONSUMER_SYNC_CANONICAL_TO_TEMPLATE}
    expected_sync = set(FORMATTER_RUNTIME_FILENAMES) | set(DCR_SYNC_EXTRA_FILENAMES)
    if synced != expected_sync:
        raise ValueError(
            "CONSUMER_SYNC_CANONICAL_TO_TEMPLATE must match runtime bundle + DCR extras"
        )
