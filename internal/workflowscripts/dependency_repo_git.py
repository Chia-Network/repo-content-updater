"""Read tracked files and repository facts at HEAD with one git process per operation.

Each helper reads the pull request's tree, never the working tree, so a file the
change does not track cannot change a fact. A path git cannot list or read, or a
search or read that exceeds its limit, returns None or a flag the caller treats
as unread.
"""

from __future__ import annotations

import codecs
import io
import posixpath
import subprocess
from typing import NamedTuple

import dependency_python_indexes as _python_indexes

_MAX_PIP_SETTING_CANDIDATES = 256
_MAX_REPO_FACT_BYTES = 8 * 1024 * 1024


def _entries(records: str) -> list[tuple[str, str]]:
    """The (path, mode) of each nonempty NUL-separated ls-tree record."""
    entries: list[tuple[str, str]] = []
    for record in records.split("\0"):
        if not record:
            continue
        meta, _separator, path = record.partition("\t")
        entries.append((path, meta.split(" ", 1)[0]))
    return entries


def files(directory: str) -> list[tuple[str, str]] | None:
    """The (path, mode) of each entry directly in `directory` at HEAD, or None when git cannot list them."""
    prefix = "" if directory in {"", "."} else f"{directory}/"
    proc = subprocess.run(
        ["git", "ls-tree", "-z", "HEAD", "--", prefix or "."],
        check=False,
        capture_output=True,
        text=True,
    )
    return None if proc.returncode != 0 else _entries(proc.stdout)


def _grep(
    needles: list[str],
    limit: int | None,
    *,
    word: bool = False,
    ignore_case: bool = False,
) -> list[str] | None:
    """The tracked paths at HEAD whose text contains any needle, or None on an error or above `limit`."""
    args = ["git", "grep", "-l", "-F", "-I", "-z"]
    if word:
        args.append("-w")
    if ignore_case:
        args.append("-i")
    for needle in needles:
        args.extend(["-e", needle])
    args.extend(["HEAD", "--"])
    proc = subprocess.run(args, check=False, capture_output=True, text=True)
    if proc.returncode not in {0, 1}:
        return None
    found = [record.removeprefix("HEAD:") for record in proc.stdout.split("\0") if record]
    return None if limit is not None and len(found) > limit else found


def grep(needle: str) -> list[str] | None:
    """The tracked paths at HEAD whose text contains `needle`, or None when git cannot search them."""
    return _grep([needle], None)


def grep_any(needles: tuple[str, ...], limit: int) -> list[str] | None:
    """The tracked paths at HEAD whose text contains any of `needles` as a whole word, ignoring case.

    Returns None on an error or when the result is above `limit`.
    """
    return _grep(list(needles), limit, word=True, ignore_case=True)


def bytes_at(rev: str, path: str) -> bytes | None:
    """The bytes of `path` at `rev`, or None when git cannot read it."""
    proc = subprocess.run(
        ["git", "show", f"{rev}:{path}"],
        check=False,
        capture_output=True,
    )
    return None if proc.returncode != 0 else proc.stdout


def text_at(rev: str, path: str) -> str | None:
    """The text of `path` at `rev`, "" when git cannot read it, or None when it is not UTF-8."""
    data = bytes_at(rev, path)
    if data is None:
        return ""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def tree() -> list[tuple[str, str]] | None:
    """The (path, mode) of every tracked entry at HEAD, or None when git cannot list them."""
    proc = subprocess.run(
        ["git", "ls-tree", "-r", "-z", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    return None if proc.returncode != 0 else _entries(proc.stdout)


def blobs(paths: list[str], limit: int) -> tuple[dict[str, bytes], bool]:
    """The bytes of each path at HEAD and whether the read limit skipped any of them.

    The paths are read in one `git cat-file --batch` after a size check, so a large repository does not run one git
    process per file and a file over the limit is not read. A path with a line break is skipped, because the batch
    protocol cannot carry it.
    """
    unique = sorted(set(paths))
    specs = [f"HEAD:{path}" for path in unique if "\n" not in path and "\r" not in path]
    overflow = len(specs) != len(unique)
    if not specs:
        return {}, overflow
    check = subprocess.run(
        ["git", "cat-file", "--batch-check"],
        input=("\n".join(specs) + "\n").encode(),
        check=False,
        capture_output=True,
    )
    if check.returncode != 0:
        return {}, True
    selected: list[str] = []
    total = 0
    for spec, line in zip(specs, check.stdout.splitlines()):
        fields = line.split()
        if len(fields) != 3:
            overflow = True
            continue
        try:
            size = int(fields[2])
        except ValueError:
            overflow = True
            continue
        if total + size > limit:
            overflow = True
            continue
        total += size
        selected.append(spec)
    if not selected:
        return {}, overflow
    batch = subprocess.run(
        ["git", "cat-file", "--batch"],
        input=("\n".join(selected) + "\n").encode(),
        check=False,
        capture_output=True,
    )
    if batch.returncode != 0:
        return {}, True
    found: dict[str, bytes] = {}
    stream = io.BytesIO(batch.stdout)
    for spec in selected:
        header = stream.readline()
        if not header:
            return found, True
        fields = header.split()
        if len(fields) != 3:
            overflow = True
            continue
        try:
            size = int(fields[2])
        except ValueError:
            return found, True
        body = stream.read(size)
        if len(body) != size:
            return found, True
        stream.read(1)
        found[spec.removeprefix("HEAD:")] = body
    return found, overflow


class RepoFacts(NamedTuple):
    """Tracked repository facts that leave a requirements file unable to replace PyPI."""

    unread: bool = False  # whether a tracked .txt or .in file cannot be read or decoded
    aliases: frozenset[str] = frozenset()  # each repository path a tracked symlink resolves to
    pip_settings: bool = False  # whether a tracked file sets a pip setting outside a requirements file
    pip_options: frozenset[str] = frozenset()  # files with a pip index option, before the read set is known
    texts: tuple[str, ...] = ()  # decoded text of each .txt or .in file a UTF-8 text search does not read


# The BOMs pip strips, longest first so a UTF-32 BOM is not read as UTF-16.
_BOM_CODECS = (
    (codecs.BOM_UTF32_LE, "utf-32-le"),
    (codecs.BOM_UTF32_BE, "utf-32-be"),
    (codecs.BOM_UTF8, "utf-8"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
)


def _utf8_text(data: bytes) -> bool:
    """Whether `data` is UTF-8 text with no NUL and no UTF-16 BOM."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")) or b"\x00" in data:
        return False
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _pip_decode(data: bytes) -> str | None:
    """`data` decoded as pip reads a requirements file, or None when its BOM-selected codec cannot decode it."""
    for bom, codec in _BOM_CODECS:
        if data.startswith(bom):
            try:
                return data[len(bom) :].decode(codec)
            except UnicodeDecodeError:
                return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _symlink_target(path: str, target: str) -> str | None:
    """The repository path a symlink at `path` points to, or None when it is absolute or outside the tree."""
    if not target or target.startswith(("/", "~")) or "\\" in target:
        return None
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
    return None if resolved in {"", ".", ".."} or resolved.startswith("../") else resolved


def repo_facts() -> RepoFacts | None:
    """The tracked-file facts that leave a requirements file unable to replace PyPI.

    A tracked .txt or .in file that text search cannot read is decoded as pip decodes it; its text matters only when
    it names a loaded requirements file. A tracked symlink whose target resolves to a loaded file also matters. A
    tracked pip.conf or pip.ini, a tracked file that names a pip index environment variable or a pip config key, or
    a pip command with an index option outside the requirements files the index check reads leaves every
    requirements file unable to replace PyPI. An unreadable file or a read over the size limit does the same.
    """
    entries = tree()
    if entries is None:
        return None
    candidates = grep_any(_python_indexes.PIP_SETTING_PATTERNS, _MAX_PIP_SETTING_CANDIDATES)
    if candidates is None:
        return None
    read_paths = {path for path, mode in entries if mode == "120000"}
    read_paths.update(path for path, mode in entries if path.endswith((".txt", ".in")) and mode.startswith("100"))
    read_paths.update(candidates)
    contents, unread = blobs(sorted(read_paths), _MAX_REPO_FACT_BYTES)
    settings = False
    aliases: set[str] = set()
    pip_options: set[str] = set()
    texts: list[str] = []
    for path, mode in entries:
        if posixpath.basename(path).lower() in _python_indexes.PIP_CONF_NAMES:
            settings = True
        if mode == "120000":
            data = contents.get(path)
            if data is None:
                unread = True
                continue
            try:
                target = data.decode("utf-8")
            except UnicodeDecodeError:
                unread = True
                continue
            resolved = _symlink_target(path, target)
            if resolved is not None:
                aliases.add(resolved)
        elif path.endswith((".txt", ".in")) and mode.startswith("100"):
            data = contents.get(path)
            if data is None or (text := _pip_decode(data)) is None:
                unread = True
            elif not _utf8_text(data):
                texts.append(text)
    for path in candidates:
        data = contents.get(path)
        if data is None:
            unread = True
            continue
        if path.endswith((".txt", ".in")):
            text = _pip_decode(data)
        else:
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                text = None
        if text is None:
            unread = True
            continue
        found_settings, found_options = _python_indexes.pip_setting_flags(path, text)
        settings = settings or found_settings
        if found_options:
            pip_options.add(path)
    return RepoFacts(unread, frozenset(aliases), settings, frozenset(pip_options), tuple(texts))


def unread_requirements(loaded: frozenset[str], facts: RepoFacts | None) -> frozenset[str]:
    """The loaded requirements files a repository-wide fact leaves unable to replace PyPI.

    A fact that leaves every file unable to replace PyPI is reported by `no_replace` instead.
    """
    if facts is None or facts.unread:
        return frozenset()
    return frozenset(
        path
        for path in loaded
        if path in facts.aliases or any(posixpath.basename(path) in text for text in facts.texts)
    )


def no_replace(loaded: frozenset[str], facts: RepoFacts | None) -> bool:
    """Whether a repository-wide fact leaves no requirements file able to replace PyPI."""
    if facts is None or facts.unread:
        return True
    return facts.pip_settings or bool(facts.pip_options - loaded)
