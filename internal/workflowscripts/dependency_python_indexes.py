"""Python package indexes a pip change may install from.

The Dependabot config selects the organization's trusted indexes. A requirements
file names its effective index with the last --index-url it reads, applying
included files in place, and any extra source keeps PyPI in play. A trusted
effective index with no extra source replaces PyPI for that file alone. A
requirements file or include that is not a blob, an option the review cannot
read, or a source that is not a trusted index or PyPI leaves that file unread,
so no change in it is trusted.
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
_ListFiles = Callable[[str], list[tuple[str, str]] | None]

_REGISTRY_RE = re.compile(r"^  [^\s#][^:]*:\s*(#.*)?$")
_REGISTRY_FIELD_RE = re.compile(r"^    ([A-Za-z0-9_-]+):[ \t]+(.+?)[ \t]*$")
_REGISTRY_FIELDS = frozenset({"type", "url", "replaces-base"})
_SCHEME_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
_DEPENDABOT_CONFIGS = (".github/dependabot.yml", ".github/dependabot.yaml")
_PYPI_INDEXES = frozenset({"https://pypi.org/simple/", "https://pypi.python.org/simple/"})
_MAX_REQUIREMENTS_FILES = 64


def _registry_scalar(value: str) -> str | None:
    """The scalar value of a registry field, or None when it is a flow mapping or a list."""
    value = value.strip()
    if not value or value[0] in "[{" or value == "-" or value.startswith("- "):
        return None
    return value[1:-1] if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'" else value


class Indexes(NamedTuple):
    """The package indexes one Python file may install from."""

    trusted: frozenset[str] = frozenset()  # each one in upstream.TRUSTED_PYTHON_INDEXES
    other: bool = False  # whether it names a source this cannot read
    index: str = ""  # the trusted index its effective --index-url replaces PyPI with, "" when PyPI stays


class DirectoryIndexes(NamedTuple):
    """The index facts of a pip directory: the configured indexes and each requirements file in it."""

    configured: Indexes = Indexes()
    files: tuple[tuple[str, Indexes], ...] = ()  # each requirements file at HEAD and its facts

    def for_path(self, path: str) -> Indexes:
        """The facts of `path`, or the configured indexes for a file with no pip options."""
        return next((found for name, found in self.files if name == path), self.configured)


def _normalized(url: str) -> str:
    return url if url.endswith("/") else f"{url}/"


def _merge(*items: Indexes) -> Indexes:
    """The trusted indexes of `items`; any other source leaves the result unread."""
    other = any(item.other for item in items)
    trusted = frozenset() if other else frozenset().union(*(item.trusted for item in items))
    return Indexes(trusted, other)


def _dependabot_indexes(text: str) -> Indexes:
    """The python-index registries of one Dependabot config. Only a URL in TRUSTED_PYTHON_INDEXES is trusted.

    Inside `registries:` every line must be a registry key or a recognised field under one, and every mention of
    `python-index` must be a parsed type field. Anything else leaves the config unread. `replaces-base` describes
    Dependabot's resolution only, so it never makes an index replace PyPI for pip.
    """
    in_registries = False
    fields: dict[str, str] | None = None
    blocks: list[dict[str, str]] = []
    unread = False
    mentions = 0
    for line in text.splitlines():
        content = line.split("#", 1)[0]
        if not content.strip():
            continue
        registry_key = False
        if not line[0].isspace():
            key, _separator, value = content.partition(":")
            header = key.strip() == "registries"
            in_registries = header and not value.strip()
            unread = unread or bool(header and value.strip())
            fields = None
        elif in_registries:
            if _REGISTRY_RE.match(line):
                fields = {}
                blocks.append(fields)
                registry_key = True
            elif fields is not None and (match := _REGISTRY_FIELD_RE.match(content)):
                name, scalar = match.group(1), _registry_scalar(match.group(2))
                if scalar is None:
                    unread = True
                elif name in _REGISTRY_FIELDS:
                    fields[name] = scalar
            else:
                unread = True
        if not registry_key:
            mentions += content.count("python-index")
    urls = [_normalized(block.get("url", "")) for block in blocks if block.get("type") == "python-index"]
    named = set(urls)
    trusted = frozenset(named & set(_upstream.TRUSTED_PYTHON_INDEXES))
    typed = sum(block.get("type") == "python-index" for block in blocks)
    other = unread or mentions != typed or bool(named - trusted - _PYPI_INDEXES)
    return Indexes(frozenset() if other else trusted, other)


def configured(read: _Read) -> Indexes:
    """The trusted indexes the repository's Dependabot configs name."""
    return _merge(*(_dependabot_indexes(read("HEAD", path)) for path in _DEPENDABOT_CONFIGS))


def _repo_include(base: str, item: str) -> str | None:
    """`item` joined to `base` as a repository path, or None when it is not a plain relative path inside the tree.

    A `..` after any other segment is rejected: normpath would collapse it across a directory that may be a symlink.
    """
    if not item or item.startswith(("/", "~")) or "\\" in item or _SCHEME_RE.match(item):
        return None
    leading_parents = True
    for segment in item.split("/"):
        if segment == "..":
            if not leading_parents:
                return None
        else:
            leading_parents = False
    joined = posixpath.normpath(posixpath.join(base, item))
    return joined if joined not in {"", ".", ".."} and not joined.startswith("../") else None


def _is_blob(mode: str) -> bool:
    return mode.startswith("100")


def _included_mode(list_files: _ListFiles, path: str) -> str | None:
    """The mode of `path` from the listing of its directory, or None when it is not listed."""
    entries = list_files(posixpath.dirname(path))
    return None if entries is None else next((mode for name, mode in entries if name == path), None)


class _Effective(NamedTuple):
    """What a requirements file and its includes leave for the next file pip reads."""

    index: str | None = None  # the effective --index-url, None when the files name none
    extra: bool = False  # whether an --extra-index-url is given
    trusted: frozenset[str] = frozenset()  # each trusted index the files name
    other: bool = False  # whether a source or include cannot be read


def _source(url: str, trusted: set[str]) -> str | None:
    """The normalized `url` when it is PyPI or a trusted index, adding it to `trusted`; None otherwise."""
    normalized = _normalized(url)
    if normalized in _PYPI_INDEXES:
        return normalized
    if normalized in _upstream.TRUSTED_PYTHON_INDEXES:
        trusted.add(normalized)
        return normalized
    return None


def _effective_file(
    path: str, configured: Indexes, read: _Read, list_files: _ListFiles, seen: frozenset[str]
) -> _Effective:
    """The effective indexes `path` and its includes leave, reading the includes in place as pip does."""
    if configured.other or path in seen or len(seen) >= _MAX_REQUIREMENTS_FILES:
        return _Effective(other=True)
    options = _python.requirements_index_options(read("HEAD", path))
    if options.unread:
        return _Effective(other=True)
    index: str | None = None
    extra = False
    trusted = set(configured.trusted)
    for option in options.options:
        if option.kind == _python.INCLUDE:
            included = _repo_include(posixpath.dirname(path), option.value)
            mode = None if included is None else _included_mode(list_files, included)
            if included is None or mode is None or not _is_blob(mode):
                return _Effective(other=True)
            child = _effective_file(included, configured, read, list_files, seen | {path})
            if child.other:
                return child
            if child.index is not None:
                index = child.index
            extra = extra or child.extra
            trusted |= child.trusted
            continue
        url = _source(option.value, trusted)
        if url is None:
            return _Effective(other=True)
        if option.kind == _python.EXTRA:
            extra = True
        else:
            index = url
    return _Effective(index, extra, frozenset(trusted))


def _file_indexes(path: str, configured: Indexes, read: _Read, list_files: _ListFiles) -> Indexes:
    """The indexes of one requirements file, with the index that replaces PyPI for that file alone."""
    effective = _effective_file(path, configured, read, list_files, frozenset())
    if effective.other:
        return Indexes(other=True)
    index = effective.index or ""
    replaces = index if not effective.extra and index in _upstream.TRUSTED_PYTHON_INDEXES else ""
    return Indexes(effective.trusted, False, replaces)


def for_directory(directory: str, configured: Indexes, read: _Read, list_files: _ListFiles) -> DirectoryIndexes:
    """The index facts of each requirements file in `directory` at HEAD and each file they include.

    A file listing that fails, or a requirements file that is not a blob, trusts none in the directory. An include
    that is not a plain repository path, an include cycle, or another package source leaves that file unread.
    """
    files = list_files(directory)
    if files is None:
        return DirectoryIndexes(Indexes(other=True))
    found: dict[str, Indexes] = {}
    for path, mode in files:
        row = _ecosystems.file_kind(path)
        if row and row.parse is _python.requirements_txt:
            if not _is_blob(mode):
                return DirectoryIndexes(Indexes(other=True))
            found[path] = _file_indexes(path, configured, read, list_files)
    return DirectoryIndexes(configured, tuple(sorted(found.items())))
