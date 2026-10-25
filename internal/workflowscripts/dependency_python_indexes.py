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
_UnreadFiles = Callable[[frozenset[str]], frozenset[str]]
_NoReplace = Callable[[frozenset[str]], bool]

_REGISTRY_RE = re.compile(r"^  [^\s#][^:]*:\s*(#.*)?$")
_REGISTRY_FIELD_RE = re.compile(r"^    ([A-Za-z0-9_-]+):[ \t]+(.+?)[ \t]*$")
_REGISTRY_FIELDS = frozenset({"type", "url"})
_SCHEME_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
_DEPENDABOT_CONFIGS = (".github/dependabot.yml", ".github/dependabot.yaml")
_PYPI_INDEXES = frozenset({"https://pypi.org/simple/", "https://pypi.python.org/simple/"})
_MAX_REQUIREMENTS_FILES = 64
_MAX_INCLUDER_CANDIDATES = 256

# A tracked file with one of these names is a pip config wherever it sits.
PIP_CONF_NAMES = frozenset({"pip.conf", "pip.ini"})
# Fixed strings a repository search uses to find a file that may set a pip option or environment variable.
PIP_SETTING_PATTERNS = (
    "PIP_INDEX_URL",
    "PIP_EXTRA_INDEX_URL",
    "PIP_FIND_LINKS",
    "PIP_NO_INDEX",
    "PIP_CONFIG_FILE",
    "--index",
    "--extra",
    "--find",
    "--no-i",
    "pip",
    "index-url",
    "extra-index-url",
    "find-links",
)
_PIP_ENV_RE = re.compile(r"\b(?:PIP_INDEX_URL|PIP_EXTRA_INDEX_URL|PIP_FIND_LINKS|PIP_NO_INDEX|PIP_CONFIG_FILE)\b")
_PIP_TOKEN_RE = re.compile(r"\bpip3?\b")
_PIP_INSTALL_RE = re.compile(
    r"\b(?:pip3?|uv\s+pip|python(?:\d+(?:\.\d+)?)?\s+-m\s+pip)\s+install\b|\bpip-(?:sync|compile)\b"
)
_PIP_LONG_OPTION_RE = re.compile(r"(?<![\w-])(--[A-Za-z0-9][A-Za-z0-9-]*)(?:=\S*)?")
_PIP_SHORT_OPTION_RE = re.compile(r"(?<!\S)-[if]\S*(?=\s|$)")
# The long option each minimum abbreviation names, so only prefixes of a real option count.
_PIP_INDEX_TARGETS = (
    ("--index-url", "--index"),
    ("--extra-index-url", "--extra"),
    ("--find-links", "--find"),
    ("--no-index", "--no-i"),
)
_PIP_CONFIG_FILES = frozenset({"setup.cfg", "tox.ini", "pyproject.toml"})
_PIP_CONFIG_SECTIONS = frozenset({"global", "install"})
_PIP_CONFIG_KEY_RE = re.compile(r"^\s*(?:index-url|extra-index-url|find-links)\s*[:=]", re.IGNORECASE)
_SECTION_RE = re.compile(r"^\s*\[([^\]]+)\]\s*$")


def _no_unread(_loaded: frozenset[str]) -> frozenset[str]:
    return frozenset()


def _never_replace(_loaded: frozenset[str]) -> bool:
    return False


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


def _inside(path: str | None) -> bool:
    """Whether `path` is a repository path, not the root and not outside the tree."""
    return path is not None and path not in {"", ".", ".."} and not path.startswith("../")


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
    return joined if _inside(joined) else None


def _is_blob(mode: str) -> bool:
    return mode.startswith("100")


def _joined_lines(text: str) -> list[str]:
    """Each line of `text` after joining a shell backslash continuation."""
    return re.sub(r"\\\r?\n", " ", text).splitlines()


def _long_index_option(word: str) -> bool:
    """Whether `word` is a long pip index option or a unique-prefix abbreviation of at least its minimum."""
    return any(target.startswith(word) and word.startswith(minimum) for target, minimum in _PIP_INDEX_TARGETS)


def _short_index_option(line: str) -> bool:
    """Whether `-i` or `-f` follows a pip install command on `line`."""
    match = _PIP_INSTALL_RE.search(line)
    if not match:
        return False
    tail = re.split(r"&&|\|\||[;|&]", line[match.end() :], maxsplit=1)[0]
    return _PIP_SHORT_OPTION_RE.search(tail) is not None


def _index_option_line(line: str) -> bool:
    """Whether `line` names pip and passes it a long index option, or a short one after an install command."""
    if not _PIP_TOKEN_RE.search(line):
        return False
    if any(_long_index_option(match.group(1)) for match in _PIP_LONG_OPTION_RE.finditer(line)):
        return True
    return _short_index_option(line)


def _pip_config_key(text: str) -> bool:
    """Whether a pip config section of `text` sets an index key."""
    section = ""
    for line in _joined_lines(text):
        header = _SECTION_RE.match(line)
        if header:
            section = header.group(1).strip().lower()
            continue
        if (section in _PIP_CONFIG_SECTIONS or section == "tool.pip" or section.startswith("tool.pip.")) and (
            _PIP_CONFIG_KEY_RE.match(line)
        ):
            return True
    return False


def pip_setting_flags(path: str, text: str) -> tuple[bool, bool]:
    """(whether `text` sets a pip setting, whether a pip command passes an index option).

    The environment names apply to any file. The config keys are read only in setup.cfg, tox.ini and pyproject.toml.
    A long option counts on a line that names pip; a short -i or -f counts only after a pip install command on the
    same joined line. Whether the file is one the requirements index check reads is decided by the caller.
    """
    settings = bool(_PIP_ENV_RE.search(text))
    if posixpath.basename(path) in _PIP_CONFIG_FILES:
        settings = settings or _pip_config_key(text)
    options = any(_index_option_line(line) for line in _joined_lines(text))
    return settings, options


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
    """The requirements files a pip directory reaches and the tracked files that include them, read once in order."""

    def __init__(
        self,
        configured: Indexes,
        read: _Read,
        list_files: _ListFiles,
        search: _Search,
        unread_files: _UnreadFiles,
        no_replace: _NoReplace,
    ) -> None:
        self._configured = configured
        self._read = read
        self._list_files = list_files
        self._search = search
        self._unread_files = unread_files
        self._no_replace = no_replace
        self._replace_blocked = False
        self._listings: dict[str, list[tuple[str, str]] | None] = {}
        self._texts: dict[str, str] = {}
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

    def _text(self, path: str) -> str:
        if path not in self._texts:
            self._texts[path] = self._read("HEAD", path)
        return self._texts[path]

    def _options_for(self, path: str) -> _python.IndexOptions:
        if path not in self._options:
            self._options[path] = _python.requirements_index_options(self._text(path))
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

    def _through_symlink(self, path: str | None) -> bool:
        """Whether a resolved path goes through a tracked symlink directory."""
        if path is None:
            return False
        parts = path.split("/")
        return any(self._mode("/".join(parts[:index])) == "120000" for index in range(1, len(parts)))

    def _candidates(self, path: str) -> list[str] | None:
        needle = posixpath.basename(path)
        if needle not in self._searched:
            found = self._search(needle)
            self._searched[needle] = None if found is not None and len(found) > _MAX_INCLUDER_CANDIDATES else found
        return self._searched[needle]

    def _consider(self, candidate: str, path: str, roots: set[str], pending: list[str]) -> None:
        """Add `candidate` to `roots` when it includes `path`; ignore it when no include option names `path`.

        A candidate that names `path` in an include option but cannot be read, parsed or resolved leaves `path`
        unread.
        """
        if candidate == path:
            return
        mode = self._mode(candidate)
        if mode is None or not _is_blob(mode) or not (text := self._text(candidate)):
            self._broken.add(path)
            return
        values = _python.requirements_includes(text)
        if values is None:
            self._broken.add(path)
            return
        options = self._options_for(candidate)
        included = self._resolve_includes(candidate)
        includes = [option for option in options.options if option.kind == _python.INCLUDE]
        resolved = [_include_text(posixpath.dirname(candidate), option.value) for option in includes]
        if path not in resolved and not any(
            target is None and self._through_symlink(value) for value, target in zip(resolved, included)
        ):
            return
        if path in included:
            if options.unread or any(item is None for item in included):
                self._broken.add(path)
            elif candidate not in roots:
                roots.add(candidate)
                pending.append(candidate)
            return
        if any(
            target is None and _inside(_include_text(posixpath.dirname(candidate), option.value))
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
        self._broken.update(self._unread_files(frozenset(self._loaded)))
        self._replace_blocked = self._no_replace(frozenset(self._loaded))
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
            if not self._replace_blocked
            and not effective.extra
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
    unread_files: _UnreadFiles = _no_unread,
    no_replace: _NoReplace = _never_replace,
) -> DirectoryIndexes:
    """The index facts of each requirements file in `directory` at HEAD.

    A file listing that fails, a requirements file that is not a blob, a reachable set of requirements files
    larger than `_MAX_REQUIREMENTS_FILES`, or more than `_MAX_INCLUDER_CANDIDATES` candidates for one name trusts
    none in the directory. An include that is not a plain repository path, an include cycle, or another package
    source leaves that file unread, and an unread file leaves every replacement unread. A file keeps its replacing
    index only when every tracked file in the repository that includes it, directly or through other includes, ends
    with that same index and names no extra source. `unread_files` names the files a repository-wide fact leaves
    unread, and `no_replace` says whether a repository-wide fact leaves no file able to replace PyPI.
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
    requirements = _Requirements(configured, read, list_files, search, unread_files, no_replace)
    constraints = set(roots)
    if not requirements.load(constraints):
        return DirectoryIndexes(Indexes(other=True))
    found = {path: requirements.facts(path, constraints) for path in roots}
    return DirectoryIndexes(configured, tuple(sorted(found.items())))
