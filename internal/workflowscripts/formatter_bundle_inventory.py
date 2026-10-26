"""Repo-authoring inventory for managed companion template sync."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

_MANAGED_FILE_ENTRY = re.compile(
    r"- name: ([^\n]+)\n    template_name: ([^\n]+)\n    repo_path: ([^\n]+)",
    re.MULTILINE,
)
# `.github/scripts/__init__.py` cannot live in this directory: unittest would
# treat workflowscripts as a package. Sync maps the template to this canonical file.
_CANONICAL_FILENAME_BY_TEMPLATE: dict[str, str] = {
    "github-scripts-init.py": "github_scripts_init.py",
}


def managed_file_index(config_text: str) -> dict[str, tuple[str, str]]:
    return {
        name: (template.strip(), repo_path.strip())
        for name, template, repo_path in _MANAGED_FILE_ENTRY.findall(config_text)
    }


def sync_canonical_to_template(config_text: str) -> tuple[tuple[str, str], ...]:
    """Derive (canonical filename, template_name) from all files[] script entries.

    Entries are returned in config.yaml order. Every files[] entry whose repo_path
    lives under `.github/scripts/` is synced from this directory.
    """
    pairs: list[tuple[str, str]] = []
    for template_name, repo_path in managed_file_index(config_text).values():
        if not repo_path.startswith(".github/scripts/"):
            continue
        canonical = _CANONICAL_FILENAME_BY_TEMPLATE.get(template_name, PurePosixPath(repo_path).name)
        pairs.append((canonical, template_name))
    return tuple(pairs)
