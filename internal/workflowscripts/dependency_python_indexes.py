"""Python package indexes a pip change may install from.

The Dependabot config selects the organization's trusted indexes. A requirements
file names its effective index with the last --index-url it reads, applying
included files in place, and any extra source keeps PyPI in play. A trusted
effective index with no extra source replaces PyPI for every install that reads
the file. A requirements file or include that is not a blob, an option the
review cannot read, or a source that is not a trusted index or PyPI leaves that
file unread, so no change in it is trusted.
"""

from __future__ import annotations

import posixpath
import re
import urllib.parse
from collections.abc import Callable
from typing import NamedTuple

import dependency_cursor_review_ecosystems as _ecosystems
import dependency_cursor_review_upstream as _upstream
import dependency_manifest_python as _python

_Read = Callable[[str, str], str]
_ListFiles = Callable[[str], list[tuple[str, str]] | None]
_Search = Callable[[str], list[str] | None]

_REGISTRY_RE = re.compile(r"^  [^\s#][^:]*:\s*(#.*)?$")
_REGISTRY_FIELD_RE = re.compile(r"^    ([A-Za-z0-9_-]+):[ \t]+(.+?)[ \t]*$")
_REGISTRY_FIELDS = frozenset({"type", "url"})
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
    """`url` with a trailing slash, and with the case of its scheme and host normalized."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return url if url.endswith("/") else f"{url}/"
    if parts.scheme and parts.netloc:
        url = urllib.parse.urlunsplit(
            (parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, parts.fragment)
        )
    return url if url.endswith("/") else f"{url}/"


def _merge(*items: Indexes) -> Indexes:
    """The trusted indexes of `items`; any other source leaves the result unread."""
    other = any(item.other for item in items)
    trusted = frozenset() if other else frozenset().union(*(item.trusted for item in items))
    return Indexes(trusted, other)


def _dependabot_indexes(text: str) -> Indexes:
    """The python-index registries of one Dependabot config. Only a URL in TRUSTED_PYTHON_INDEXES is trusted.

    Inside `registries:` every line must be a registry key or a recognised field under one, and every mention of
    `python-index` must be a parsed type field. A field written twice under one registry is ambiguous, and anything
    else that is not read leaves the config unread. `replaces-base` is not recorded: only a requirements file's
    effective index replaces PyPI for pip.
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
                if scalar is None or name in fields:
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


def _include_text(base: str, item: str) -> str | None:
    """`item` joined to `base` as a repository path, or None when it is not a plain relative path."""
    if not item or item.startswith(("/", "~")) or "\\" in item or _SCHEME_RE.match(item):
        return None
    return posixpath.normpath(posixpath.join(base, item))


def _repo_include(base: str, item: str) -> str | None:
    """`item` joined to `base` as a repository path, or None when it is not a plain relative path inside the tree.

    A `..` after any other segment is rejected: normpath would collapse it across a directory that may be a symlink.
    """
    joined = _include_text(base, item)
    if joined is None:
        return None
    leading_parents = True
    for segment in item.split("/"):
        if segment == "..":
            if not leading_parents:
                return None
        else:
            leading_parents = False
    return joined if joined not in {"", ".", ".."} and not joined.startswith("../") else None


def _is_blob(mode: str) -> bool:
    return mode.startswith("100")


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


class _Requirements:
    """The requirements files one directory reaches, each read once and resolving its includes in pip's order."""

    def __init__(self, configured: Indexes, read: _Read, list_files: _ListFiles, search: _Search) -> None:
        self._configured = configured
        self._read = read
        self._list_files = list_files
        self._search = search
        self._listings: dict[str, list[tuple[str, str]] | None] = {}
        self._options: dict[str, _python.IndexOptions] = {}
        self._included: dict[str, tuple[str | None, ...]] = {}
        self._effective: dict[str, _Effective] = {}
        self._parents: dict[str, set[str]] = {}  # each included path and the files that include it
        self._broken: set[str] = set()
        self._loaded: set[str] = set()
        self._searched: dict[str, list[str] | None] = {}

    def _listing(self, directory: str) -> list[tuple[str, str]] | None:
        directory = directory or "."
        if directory not in self._listings:
            self._listings[directory] = self._list_files(directory)
        return self._listings[directory]

    def _mode(self, path: str) -> str | None:
        entries = self._listing(posixpath.dirname(path))
        return None if entries is None else next((mode for name, mode in entries if name == path), None)

    def _include(self, path: str, item: str) -> str | None:
        """The included path when it is a blob inside the tree, or None."""
        included = _repo_include(posixpath.dirname(path), item)
        if included is None:
            return None
        mode = self._mode(included)
        return included if mode is not None and _is_blob(mode) else None

    def _options_for(self, path: str) -> _python.IndexOptions:
        if path not in self._options:
            self._options[path] = _python.requirements_index_options(self._read("HEAD", path))
        return self._options[path]

    def _resolve_includes(self, path: str) -> tuple[str | None, ...]:
        """The included path of each include option in `path`, in pip's order."""
        if path not in self._included:
            self._included[path] = tuple(
                self._include(path, option.value)
                for option in self._options_for(path).options
                if option.kind == _python.INCLUDE
            )
        return self._included[path]

    def _candidates(self, path: str) -> list[str] | None:
        needle = posixpath.basename(path)
        if needle not in self._searched:
            self._searched[needle] = self._search(needle)
        return self._searched[needle]

    def _consider(self, candidate: str, path: str, roots: set[str], pending: list[str]) -> None:
        """Add `candidate` to `roots` when it includes `path`, or leave `path` unread when that cannot be decided."""
        if candidate == path:
            return
        mode = self._mode(candidate)
        if mode is None or not _is_blob(mode):
            self._broken.add(path)
            return
        options = self._options_for(candidate)
        included = self._resolve_includes(candidate)
        includes = [option for option in options.options if option.kind == _python.INCLUDE]
        if path in included:
            if options.unread or any(item is None for item in included):
                self._broken.add(path)
            elif candidate not in roots:
                roots.add(candidate)
                pending.append(candidate)
            return
        if any(
            target is None and _include_text(posixpath.dirname(candidate), option.value) == path
            for option, target in zip(includes, included)
        ):
            self._broken.add(path)
            return
        if options.unread:
            self._broken.add(path)

    def load(self, roots: set[str]) -> bool:
        """Read every requirements file `roots` reaches and every tracked file that includes one.

        `roots` gains each tracked file that includes a file it reaches. Return False when the set exceeds
        `_MAX_REQUIREMENTS_FILES`.
        """
        pending = list(roots)
        while pending:
            path = pending.pop()
            if path in self._loaded:
                continue
            if len(self._loaded) >= _MAX_REQUIREMENTS_FILES:
                return False
            self._loaded.add(path)
            if self._options_for(path).unread:
                self._broken.add(path)
            for included in self._resolve_includes(path):
                if included is None:
                    self._broken.add(path)
                else:
                    self._parents.setdefault(included, set()).add(path)
                    pending.append(included)
            candidates = self._candidates(path)
            if candidates is None:
                self._broken.add(path)
                continue
            for candidate in candidates:
                self._consider(candidate, path, roots, pending)
        return True

    def _effective_at(self, path: str, stack: frozenset[str]) -> _Effective:
        if path in self._effective:
            return self._effective[path]
        if path in stack or path in self._broken:
            return _Effective(other=True)
        index: str | None = None
        extra = False
        trusted = set(self._configured.trusted)
        resolved = iter(self._resolve_includes(path))
        for option in self._options_for(path).options:
            if option.kind == _python.INCLUDE:
                included = next(resolved)
                if included is None:
                    return _Effective(other=True)
                child = self._effective_at(included, stack | {path})
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
        found = _Effective(index, extra, frozenset(trusted))
        self._effective[path] = found
        return found

    def effective(self, path: str) -> _Effective:
        """The effective indexes `path` and its includes leave."""
        return _Effective(other=True) if self._configured.other else self._effective_at(path, frozenset())

    def _includes(self, path: str) -> set[str]:
        """Every path that includes `path`, directly or through other includes."""
        found: set[str] = set()
        pending = list(self._parents.get(path, ()))
        while pending:
            parent = pending.pop()
            if parent not in found:
                found.add(parent)
                pending.extend(self._parents.get(parent, ()))
        return found

    def replaces_pypi(self, path: str, index: str, roots: set[str]) -> bool:
        """Whether every requirements file in `roots` that includes `path` ends with `index` and no extra source.

        An unread file in `roots` may include `path` through a line this cannot read, so it leaves every
        replacement unread.
        """
        if any(self.effective(root).other for root in roots):
            return False
        return all(
            (found := self.effective(parent)).index == index and not found.extra
            for parent in self._includes(path) & roots
        )

    def facts(self, path: str, roots: set[str]) -> Indexes:
        """The indexes of one requirements file, with the index that replaces PyPI for the whole install."""
        effective = self.effective(path)
        if effective.other:
            return Indexes(other=True)
        index = effective.index or ""
        replaces = (
            index
            if not effective.extra
            and index in _upstream.TRUSTED_PYTHON_INDEXES
            and self.replaces_pypi(path, index, roots)
            else ""
        )
        return Indexes(effective.trusted, False, replaces)


def for_directory(
    directory: str,
    configured: Indexes,
    read: _Read,
    list_files: _ListFiles,
    search: _Search,
) -> DirectoryIndexes:
    """The index facts of each requirements file in `directory` at HEAD.

    A file listing that fails, a requirements file that is not a blob, or a reachable set of requirements files
    larger than `_MAX_REQUIREMENTS_FILES` trusts none in the directory. An include that is not a plain repository
    path, an include cycle, or another package source leaves that file unread, and an unread file leaves every
    replacement unread. A file keeps its replacing index only when every tracked file in the repository that
    includes it, directly or through other includes, ends with that same index and names no extra source.
    """
    files = list_files(directory)
    if files is None:
        return DirectoryIndexes(Indexes(other=True))
    roots: set[str] = set()
    for path, mode in files:
        row = _ecosystems.file_kind(path)
        if row and row.parse is _python.requirements_txt:
            if not _is_blob(mode):
                return DirectoryIndexes(Indexes(other=True))
            roots.add(path)
    requirements = _Requirements(configured, read, list_files, search)
    constraints = set(roots)
    if not requirements.load(constraints):
        return DirectoryIndexes(Indexes(other=True))
    found = {path: requirements.facts(path, constraints) for path in roots}
    return DirectoryIndexes(configured, tuple(sorted(found.items())))
