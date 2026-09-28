"""Repo-authoring inventory (sync + manifest generation; not consumer runtime)."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

from formatter_runtime_bundle import FORMATTER_RUNTIME_FILENAMES

_DCR_WORKFLOW = "dependency-cursor-review"
_MANAGED_FILE_ENTRY = re.compile(
    r"- name: ([^\n]+)\n    template_name: ([^\n]+)\n    repo_path: ([^\n]+)",
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

# Repo-content-updater authoring mirror only (not consumer trusted checkout).
AUTHORING_ONLY_SYNC_CANONICAL_TO_TEMPLATE: tuple[tuple[str, str], ...] = (
    ("formatter_bundle_inventory.py", "formatter-bundle-inventory.py"),
)

_SYNC_EMIT_ONLY_TEMPLATES: frozenset[str] = frozenset(
    {"dependency-cursor-review-trusted-scripts.paths"}
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


def managed_file_index(config_text: str) -> dict[str, tuple[str, str]]:
    return {
        name: (template.strip(), repo_path.strip())
        for name, template, repo_path in _MANAGED_FILE_ENTRY.findall(config_text)
    }


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


def consumer_sync_canonical_to_template(
    config_text: str,
) -> tuple[tuple[str, str], ...]:
    """Derive (canonical filename, template_name) from config companions + files[]."""
    companions = parse_dcr_companion_files(config_text)
    index = managed_file_index(config_text)
    pairs: list[tuple[str, str]] = []
    for name in companions:
        entry = index.get(name)
        if entry is None:
            continue
        template_name, repo_path = entry
        if not repo_path.startswith(".github/scripts/"):
            continue
        if template_name in _SYNC_EMIT_ONLY_TEMPLATES:
            continue
        canonical = PurePosixPath(repo_path).name
        pairs.append((canonical, template_name))
    return tuple(pairs)


def sync_canonical_to_template(config_text: str) -> tuple[tuple[str, str], ...]:
    return (
        *consumer_sync_canonical_to_template(config_text),
        *AUTHORING_ONLY_SYNC_CANONICAL_TO_TEMPLATE,
    )


def trusted_dcr_script_repo_paths(config_text: str) -> tuple[str, ...]:
    """Consumer trusted-git-path-checkout manifest (.github/scripts/* only)."""
    companion_names = parse_dcr_companion_files(config_text)
    name_to_path = {
        name: repo_path
        for name, _template, repo_path in _MANAGED_FILE_ENTRY.findall(config_text)
    }
    ordered: list[str] = [*_TRUSTED_MANIFEST_ONLY_REPO_PATHS]
    for name in companion_names:
        path = name_to_path.get(name)
        if path and path.startswith(".github/scripts/"):
            ordered.append(path)
    return tuple(ordered)


def managed_formatter_sync_pairs(config_text: str) -> tuple[tuple[str, str], ...]:
    """Template name, canonical filename (consumer sync face)."""
    return tuple(
        (template, canonical)
        for canonical, template in consumer_sync_canonical_to_template(config_text)
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
    synced = {canonical for canonical, _ in consumer_sync_canonical_to_template(config_text)}
    missing_runtime = set(FORMATTER_RUNTIME_FILENAMES) - synced
    if missing_runtime:
        raise ValueError(
            "config companions missing runtime bundle files: "
            f"{sorted(missing_runtime)}"
        )
