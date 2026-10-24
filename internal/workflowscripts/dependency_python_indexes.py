"""Python package indexes a pip change may install from.

The Dependabot config can select among the organization's trusted indexes, and a
requirements file can name indexes for its directory and the files it includes.
A directory is read when every source it names is a trusted index. Any other
source or an unreadable config leaves the directory unread, so no change there
is trusted.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Callable
from typing import NamedTuple

import dependency_cursor_review_ecosystems as _ecosystems
import dependency_cursor_review_upstream as _upstream
import dependency_manifest_python as _python

_Read = Callable[[str, str], str]
_ListFiles = Callable[[str], list[str] | None]

_REGISTRY_RE = re.compile(r"^  [^\s#][^:]*:\s*(#.*)?$")
_REGISTRY_FIELD_RE = re.compile(r"""^    (type|url|replaces-base):\s*(["']?)([^"'\s#]+)\2\s*(#.*)?$""")
_SCHEME_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
_DEPENDABOT_CONFIGS = (".github/dependabot.yml", ".github/dependabot.yaml")
_MAX_REQUIREMENTS_FILES = 64


class Indexes(NamedTuple):
    """The Python package indexes pip may install from besides PyPI, named by the Dependabot config or a
    requirements file."""

    trusted: frozenset[str] = frozenset()  # each one in upstream.TRUSTED_PYTHON_INDEXES
    other: bool = False  # whether it names any other one, or one this cannot read
    replaces_pypi: bool = False  # whether a trusted index replaces PyPI rather than adding to it


def _normalized(url: str) -> str:
    return url if url.endswith("/") else f"{url}/"


def _indexes(
    urls: list[str],
    unread: bool,
    replaces_pypi: bool = False,
    *more: Indexes,
    extra: bool = False,
) -> Indexes:
    """Indexes of `urls` and `more`. Any index that is not in TRUSTED_PYTHON_INDEXES, or `unread`, trusts none.

    An extra index keeps PyPI as a source, so no index replaces it.
    """
    urls = [_normalized(url) for url in urls]
    trusted = frozenset(url for url in urls if url in _upstream.TRUSTED_PYTHON_INDEXES)
    other = unread or len(trusted) != len(set(urls)) or any(item.other for item in more)
    replaces = not other and not extra and (replaces_pypi or any(item.replaces_pypi for item in more))
    return Indexes(
        frozenset() if other else trusted.union(*(item.trusted for item in more)),
        other,
        replaces,
    )


def _dependabot_indexes(text: str) -> Indexes:
    """The python-index registries of one Dependabot config. Only a URL in TRUSTED_PYTHON_INDEXES is trusted."""
    fields: dict[str, str] | None = None
    blocks: list[dict[str, str]] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            fields = {} if line.split("#", 1)[0].strip() == "registries:" else None
            blocks += [fields] if fields is not None else []
        elif fields is not None and _REGISTRY_RE.match(line):
            fields = {}
            blocks.append(fields)
        elif fields is not None and (match := _REGISTRY_FIELD_RE.match(line)):
            fields[match.group(1)] = match.group(3)
    urls = [block.get("url", "") for block in blocks if block.get("type") == "python-index"]
    replaces = any(
        block.get("type") == "python-index" and block.get("replaces-base", "").lower() == "true" for block in blocks
    )
    # Every python-index this reads has a URL, or the config is not read and nothing is trusted.
    return _indexes(urls, len(urls) != text.count("python-index"), replaces)


def configured(read: _Read) -> Indexes:
    """The trusted indexes the repository's Dependabot configs name."""
    return _indexes(
        [],
        False,
        False,
        *(_dependabot_indexes(read("HEAD", path)) for path in _DEPENDABOT_CONFIGS),
    )


def _repo_include(base: str, item: str) -> str | None:
    """`item` joined to `base` as a repository path, or None when it is not a plain relative path inside the tree."""
    if not item or item.startswith(("/", "~")) or "\\" in item or _SCHEME_RE.match(item):
        return None
    joined = posixpath.normpath(posixpath.join(base, item))
    return joined if joined not in {"", ".", ".."} and not joined.startswith("../") else None


def for_directory(directory: str, configured: Indexes, read: _Read, list_files: _ListFiles) -> Indexes:
    """`configured` with the indexes of the requirements files in `directory` at HEAD and each file they include.

    A file listing that fails, an include that is not a plain repository path, or another package source trusts none.
    Any --extra-index-url keeps PyPI as a source.
    """
    files = list_files(directory)
    if files is None:
        return Indexes(other=True)
    pending = [path for path in files if (row := _ecosystems.file_kind(path)) and row.parse is _python.requirements_txt]
    seen: set[str] = set()
    urls: list[str] = []
    replaces = False
    extra = False
    while pending:
        path = pending.pop()
        if path in seen:
            continue
        seen.add(path)
        options = _python.requirements_index_options(read("HEAD", path))
        included = [_repo_include(posixpath.dirname(path), item) for item in options.includes]
        if options.unread or None in included or len(seen) > _MAX_REQUIREMENTS_FILES:
            return Indexes(other=True)
        urls += options.urls
        replaces = replaces or options.replaces_pypi
        extra = extra or options.extra_index_url
        pending += [item for item in included if item is not None]
    return _indexes(urls, False, replaces, configured, extra=extra)
