"""Inspect the PR diff and changed-file list for literal review changes.

The diff and file list are untrusted data and are never executed. Paths come
from the PR files API list, and the same module owns the literal diff checks.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")
SHA256_VALUE = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")
NAME_CHARS = r"A-Za-z0-9._~-"
VERSION_CHARS = r"A-Za-z0-9._+-"
BINDING_CHARS = r"A-Za-z0-9._~+/=-"
HUNK_HEADER = re.compile(r"^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@")
PEP503_SEPARATORS = re.compile(r"[-_.]+")
PIP_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
PIP_VERSION_SPLIT = re.compile(r"-(?=[0-9])")
PACKAGE_SUFFIX = re.compile(r"\.(?:tar\.gz|tar\.bz2|tar\.xz|zip|whl|egg)$")
LOCK_WINDOW = 24
MAX_PR_FILES = 3000


@dataclass(frozen=True)
class Hunk:
    """The ordered lines of one unified-diff hunk, as (kind, text) pairs."""

    lines: tuple[tuple[str, str], ...] = ()


def read_changed_files(path: str | None) -> tuple[str, ...] | None:
    """The paths listed by the PR files API, or None when the list is unusable."""
    if not path:
        return None
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    paths = tuple(line for line in text.splitlines() if line)
    if not paths or len(paths) >= MAX_PR_FILES:
        return None
    return paths


def _walk(text: str) -> Iterator[tuple[int, str, str, int]]:
    """Yield (line number, kind, body, hunk index) for each diff content line.

    Lines outside a hunk get index -1. Headers are recognised only outside a
    hunk, so an in-hunk line beginning with `+++` is content.
    """
    in_hunk = False
    index = -1
    old_remaining = new_remaining = 0
    for number, line in enumerate(text.splitlines(), 1):
        if line.startswith("diff "):
            in_hunk = False
        elif line.startswith("@@"):
            in_hunk = True
            index += 1
            match = HUNK_HEADER.match(line)
            old_remaining, new_remaining = (int(match.group(1) or 1), int(match.group(2) or 1)) if match else (1, 1)
        elif in_hunk:
            if line.startswith("+"):
                yield number, "+", line[1:], index
                new_remaining -= 1
            elif line.startswith("-"):
                yield number, "-", line[1:], index
                old_remaining -= 1
            elif line.startswith(" "):
                yield number, " ", line[1:], index
                old_remaining -= 1
                new_remaining -= 1
            elif not line.startswith("\\"):
                in_hunk = False
                continue
            if old_remaining <= 0 and new_remaining <= 0:
                in_hunk = False
        elif not line.startswith(("--- ", "+++ ")):
            if line.startswith("+"):
                yield number, "+", line[1:], -1
            elif line.startswith("-"):
                yield number, "-", line[1:], -1


def parse_hunks(text: str) -> tuple[Hunk, ...]:
    """The hunks of a diff; content outside hunks becomes one fallback hunk."""
    hunks: list[Hunk] = []
    loose: list[tuple[str, str]] = []
    lines: list[tuple[str, str]] = []
    current = -1
    for _number, kind, body, index in _walk(text):
        if index < 0:
            loose.append((kind, body))
        elif index != current:
            if lines:
                hunks.append(Hunk(tuple(lines)))
            lines = [(kind, body)]
            current = index
        else:
            lines.append((kind, body))
    if lines:
        hunks.append(Hunk(tuple(lines)))
    if hunks or not loose:
        return tuple(hunks)
    return (Hunk(tuple([row for row in loose if row[0] == "+"] + [row for row in loose if row[0] == "-"])),)


def normalize_name(name: str, ecosystem: str = "") -> str:
    """The comparison form of a package name in one ecosystem."""
    return PEP503_SEPARATORS.sub("-", name).lower() if ecosystem == "pip" else name


def _pip_parts(text: str) -> tuple[str, str]:
    """The name and version parts of a package or distribution filename token."""
    match = PIP_VERSION_SPLIT.search(text)
    if match is None:
        return text, ""
    version = text[match.end() :].split("-", 1)[0]
    return text[: match.start()], PACKAGE_SUFFIX.sub("", version)


def name_matches(line: str, name: str, ecosystem: str = "") -> bool:
    """True when the whole package name appears on the line."""
    if ecosystem == "pip":
        wanted = normalize_name(name, ecosystem)
        return any(
            normalize_name(_pip_parts(match.group(0))[0], ecosystem) == wanted for match in PIP_TOKEN.finditer(line)
        )
    return token(name, NAME_CHARS).search(line) is not None


def version_matches(line: str, version: str, ecosystem: str = "") -> bool:
    """True when the whole version appears on the line."""
    if ecosystem == "pip":
        for match in PIP_TOKEN.finditer(line):
            text = match.group(0)
            _name, found = _pip_parts(text)
            if found == version or (not found and text == version):
                return True
        return False
    return token(version, VERSION_CHARS).search(line) is not None


def hunk_near(hunk: Hunk, name: str, window: int, ecosystem: str = "", side: str = "new") -> list[tuple[str, str]]:
    """The (kind, text) lines within `window` of the package name on one side."""
    excluded = "-" if side == "new" else "+"
    lines = [(kind, text) for kind, text in hunk.lines if kind != excluded]
    anchors = [index for index, (_kind, text) in enumerate(lines) if name_matches(text, name, ecosystem)]
    selected = {
        index for anchor in anchors for index in range(max(0, anchor - window), min(len(lines), anchor + window + 1))
    }
    return [lines[index] for index in sorted(selected)]


def hunk_matches(hunk: Hunk, name: str, new_version: str, prev_version: str, window: int, ecosystem: str = "") -> bool:
    """True when both versions are anchored to the package name in one hunk."""

    def found(version: str, side: str) -> bool:
        kind = "+" if side == "new" else "-"
        return any(
            line_kind == kind and version_matches(text, version, ecosystem)
            for line_kind, text in hunk_near(hunk, name, window, ecosystem, side)
        )

    return found(new_version, "new") and found(prev_version, "old")


def token(text: str, chars: str) -> re.Pattern[str]:
    """A literal match that cannot start or end inside a longer token."""
    return re.compile(rf"(?<![{chars}]){re.escape(text)}(?![{chars}])")


def binding_on_added(binding: str, added: Sequence[str]) -> bool:
    """True when the literal binding appears on an added line."""
    if not binding:
        return False
    pattern = token(binding, BINDING_CHARS)
    return any(pattern.search(line) for line in added)


def locked_hashes(name: str, hunks: Sequence[Hunk]) -> frozenset[str]:
    """The sha256 values the pip lock lists near this package's entry."""
    hashes: set[str] = set()
    for hunk in hunks:
        for kind, line in hunk_near(hunk, name, LOCK_WINDOW, "pip"):
            if kind == "+":
                hashes.update(match.group(0) for match in SHA256_VALUE.finditer(line))
    return frozenset(hashes)


def added_lines(text: str) -> list[tuple[int, str]]:
    """The added content lines of a diff with their original line numbers."""
    return [(number, body) for number, kind, body, _index in _walk(text) if kind == "+"]
