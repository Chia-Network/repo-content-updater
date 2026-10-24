"""The one table of dependency files and the scan policy of each ecosystem.

A FileKind row names a file by its name or path shape, its ecosystem, its
role and the grammar that reads it (None when no grammar does). An Ecosystem
row carries the policy. A change in a `warn` ecosystem, or an action ref that
can move, is never scanned and never benign: decide() reports it inconclusive
with a named warning and does not block on it.

Roles: a manifest declares dependencies; a lock records the installed copies
of the dependencies the manifest beside it declares; checksums hash the
versions the manifest beside them names, so every version a checksum file adds
or drops must be one the manifest beside it adds or drops.

Each grammar returns (name, version, top, text) entries. An entry's text may
change only with its version. In a line grammar the text is the line with the
version masked, so it may not change at all; in a record grammar (a lock copy,
a provider block) it is the whole record, which changes with the version.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import PurePosixPath
from typing import NamedTuple

import dependency_cursor_review_upstream as upstream
from dependency_cursor_review_versions import moving_ref
from dependency_manifest_go import go_mod, go_sum
from dependency_manifest_lines import Parsed, dockerfile_from, terraform_config, terraform_lock, workflow_uses
from dependency_manifest_npm import package_json, package_lock, yarn_lock
from dependency_manifest_python import requirements

# Why a change is not scanned. Docker images and Terraform providers have no
# source tree to read; a moving tag can resolve to another commit after the review.
UNSCANNABLE_ECOSYSTEM = "unscannable_ecosystem"
MOVING_REF = "moving_ref"
WARN_REASONS = frozenset({UNSCANNABLE_ECOSYSTEM, MOVING_REF})

MANIFEST, LOCK, CHECKSUMS = "manifest", "lock", "checksums"


def _no_repo(_name: str, _version: str) -> str:
    return ""


class Ecosystem(NamedTuple):
    name: str
    warn: str = ""  # the warn reason for every change, "" when changes are scanned
    moving_refs: bool = False  # a ref that is neither a release tag nor a commit is MOVING_REF
    repo: Callable[[str, str], str] = _no_repo  # GitHub repository of (name, exact version)


class FileKind(NamedTuple):
    ecosystem: Ecosystem
    role: str
    parse: Callable[[str], Parsed | None] | None
    names: frozenset[str] = frozenset()  # exact file names
    match: Callable[[PurePosixPath], bool] | None = None  # any other path shape
    records: bool = False  # entries are whole records, not lines


NPM = Ecosystem("npm", repo=upstream.npm)
PIP = Ecosystem("pip", repo=upstream.pypi)
GO = Ecosystem("go", repo=upstream.go)
ACTIONS = Ecosystem("github-actions", moving_refs=True, repo=upstream.action)
DOCKER = Ecosystem("docker", warn=UNSCANNABLE_ECOSYSTEM)
TERRAFORM = Ecosystem("terraform", warn=UNSCANNABLE_ECOSYSTEM)
# Ecosystems with no grammar: a manifest change is a gap, and so is a lock change without a primary change beside it.
CARGO, BUNDLER, COMPOSER, SWIFT, NUGET = (
    Ecosystem(name) for name in ("cargo", "bundler", "composer", "swift", "nuget")
)


def _requirements(path: PurePosixPath) -> bool:
    return path.suffix == ".txt" and (path.name.startswith("requirements") or "requirements" in path.parts[:-1])


def _workflow(path: PurePosixPath) -> bool:
    in_workflows = "/.github/workflows/" in f"/{path}"
    return path.suffix in {".yml", ".yaml"} and (in_workflows or path.stem == "action")


def _dockerfile(path: PurePosixPath) -> bool:
    return path.name == "Dockerfile" or path.name.startswith("Dockerfile.")


def _dotnet_project(path: PurePosixPath) -> bool:
    return path.suffix in {".csproj", ".fsproj", ".vbproj"}


def _terraform(path: PurePosixPath) -> bool:
    return path.suffix == ".tf"


_FILES = (
    FileKind(NPM, MANIFEST, package_json, frozenset({"package.json"})),
    FileKind(NPM, LOCK, package_lock, frozenset({"package-lock.json", "npm-shrinkwrap.json"}), records=True),
    FileKind(NPM, LOCK, yarn_lock, frozenset({"yarn.lock"}), records=True),
    FileKind(NPM, LOCK, None, frozenset({"pnpm-lock.yaml"})),
    FileKind(GO, MANIFEST, go_mod, frozenset({"go.mod"})),
    FileKind(GO, CHECKSUMS, go_sum, frozenset({"go.sum"}), records=True),
    FileKind(
        PIP, MANIFEST, requirements, frozenset({"pyproject.toml", "setup.py", "setup.cfg", "Pipfile"}), _requirements
    ),
    FileKind(PIP, LOCK, None, frozenset({"poetry.lock", "Pipfile.lock"})),
    FileKind(ACTIONS, MANIFEST, workflow_uses, match=_workflow),
    FileKind(DOCKER, MANIFEST, dockerfile_from, match=_dockerfile),
    FileKind(TERRAFORM, MANIFEST, terraform_lock, frozenset({".terraform.lock.hcl"}), records=True),
    FileKind(TERRAFORM, MANIFEST, terraform_config, match=_terraform),
    FileKind(CARGO, MANIFEST, None, frozenset({"Cargo.toml"})),
    FileKind(CARGO, LOCK, None, frozenset({"Cargo.lock"})),
    FileKind(BUNDLER, LOCK, None, frozenset({"Gemfile.lock"})),
    FileKind(COMPOSER, LOCK, None, frozenset({"composer.lock"})),
    FileKind(SWIFT, MANIFEST, None, frozenset({"Package.swift", "Package.resolved"})),
    FileKind(NUGET, MANIFEST, None, frozenset({"packages.config", "Directory.Packages.props"}), _dotnet_project),
)
_BY_NAME = {row.ecosystem.name: row.ecosystem for row in _FILES}


def file_kind(path: str) -> FileKind | None:
    """The row for a changed path, or None when it is not a dependency file."""
    posix = PurePosixPath(path)
    return next((row for row in _FILES if posix.name in row.names or (row.match and row.match(posix))), None)


def beside(ecosystem: Ecosystem, role: str, directory: str) -> list[tuple[str, FileKind]]:
    """Paths of the fixed-name files with this role and a grammar in `directory`, with their rows."""
    return [
        (str(PurePosixPath(directory) / name), row)
        for row in _FILES
        if row.ecosystem == ecosystem and row.role == role and row.parse is not None
        for name in sorted(row.names)
    ]


def warn_reason(ecosystem: str, old: str, new: str) -> str:
    """Why a change in `ecosystem` from `old` to `new` is not scanned, or "" when it is scanned."""
    row = _BY_NAME.get(ecosystem)
    if row is None:
        return ""
    if row.warn:
        return row.warn
    return MOVING_REF if row.moving_refs and any(ref and moving_ref(ref) for ref in (old, new)) else ""


def upstream_repo(ecosystem: str, name: str, version: str) -> str:
    """The GitHub repository a change is scanned from, or "" when the ecosystem has none or the lookup failed."""
    row = _BY_NAME.get(ecosystem)
    return row.repo(name, version) if row else ""
