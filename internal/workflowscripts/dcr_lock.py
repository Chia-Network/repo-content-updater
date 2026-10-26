"""Inspect the PR diff for lock, manifest and literal review changes.

The diff text is untrusted data and is never executed. Each changed file's old
and new sides are rebuilt per hunk and parsed by one small line parser, then
compared by package name and version. Changed packages that are not in the
update list are returned so the caller can mark them unverified. The same
module owns the literal diff checks, the diff bundle and its IOC scan.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

from dcr_sources import FetchError

MAX_DIFF_BYTES = 2 * 1024 * 1024
BIDI_CONTROL = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")
SHA256_VALUE = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")
NAME_CHARS = r"A-Za-z0-9._~-"
VERSION_CHARS = r"A-Za-z0-9._+-"
BINDING_CHARS = r"A-Za-z0-9._~+/=-"
PEP503_SEPARATORS = re.compile(r"[-_.]+")


class LockChange(NamedTuple):
    """One package whose version differs between the old and new side of a file."""

    ecosystem: str
    name: str
    prev_version: str
    new_version: str


@dataclass(frozen=True)
class Hunk:
    """The old and new lines of one unified-diff hunk, context included."""

    old: list[str]
    new: list[str]


@dataclass(frozen=True)
class FileDiff:
    """One changed file and its hunks."""

    path: str
    hunks: tuple[Hunk, ...]


@dataclass(frozen=True)
class FileFormat:
    """A path pattern, its ecosystem and the line parser for one file format."""

    pattern: re.Pattern[str]
    ecosystem: str
    parser: Callable[[Sequence[str]], list[tuple[str, str]]]


def _header_path(line: str) -> str | None:
    """The path from a `---` or `+++` header, or None for /dev/null."""
    value = line[4:].strip()
    if value == "/dev/null":
        return None
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    return value[2:] if value.startswith(("a/", "b/")) else value


def parse_diff(text: str) -> tuple[FileDiff, ...]:
    """Split a unified diff into changed files and hunks, keeping context lines."""
    files: list[FileDiff] = []
    path: str | None = None
    old_path: str | None = None
    hunks: list[Hunk] = []
    hunk: Hunk | None = None

    def flush_hunk() -> None:
        nonlocal hunk
        if hunk is not None and (hunk.old or hunk.new):
            hunks.append(hunk)
        hunk = None

    def flush_file() -> None:
        flush_hunk()
        if path is not None and hunks:
            files.append(FileDiff(path, tuple(hunks)))
        hunks.clear()

    for line in text.splitlines():
        if line.startswith("diff --git "):
            flush_file()
            path = old_path = None
        elif line.startswith("--- "):
            old_path = _header_path(line)
        elif line.startswith("+++ "):
            path = _header_path(line) or old_path
        elif line.startswith("@@"):
            flush_hunk()
            hunk = Hunk([], [])
        elif hunk is not None:
            if line.startswith("+"):
                hunk.new.append(line[1:])
            elif line.startswith("-"):
                hunk.old.append(line[1:])
            elif line.startswith(" "):
                hunk.old.append(line[1:])
                hunk.new.append(line[1:])
    flush_file()
    return tuple(files)


_JSON_KEY = re.compile(r'^\s*"(?P<key>[^"]+)"\s*:\s*\{\s*$')
_JSON_VERSION = re.compile(r'^\s*"version"\s*:\s*"(?P<version>[^"]+)"')
_JSON_RESERVED = frozenset(
    {
        "",
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
        "packages",
        "version",
        "lockfileVersion",
        "requires",
        "name",
    }
)
_NODE_MODULES = "node_modules/"


def _lock_name(key: str) -> str:
    """The package name a package-lock key refers to, or "" when it is not a package."""
    if key in _JSON_RESERVED:
        return ""
    index = key.rfind(_NODE_MODULES)
    if index < 0:
        return key
    parts = key[index + len(_NODE_MODULES) :].split("/")
    if not parts or not parts[0]:
        return ""
    if parts[0].startswith("@"):
        return f"{parts[0]}/{parts[1]}" if len(parts) > 1 and parts[1] else ""
    return parts[0]


def _npm_lock(lines: Sequence[str]) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    name = ""
    for line in lines:
        key = _JSON_KEY.match(line)
        if key:
            name = _lock_name(key.group("key"))
            continue
        version = _JSON_VERSION.match(line)
        if version and name:
            entries.append((name, version.group("version")))
    return entries


_YARN_NAME = re.compile(r"(@?[^@\"\s,]+)@")
_YARN_VERSION = re.compile(r'^\s+version(?::\s*|\s+)"?(?P<version>[^"\s]+)"?\s*$')


def _yarn_names(header: str) -> list[str]:
    names: list[str] = []
    for part in header.rstrip().rstrip(":").split(","):
        match = _YARN_NAME.match(part.strip().strip('"'))
        if match and match.group(1) not in names:
            names.append(match.group(1))
    return names


def _yarn_lock(lines: Sequence[str]) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    names: list[str] = []
    for line in lines:
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            names = _yarn_names(line)
            continue
        version = _YARN_VERSION.match(line)
        if version:
            entries.extend((name, version.group("version")) for name in names)
    return entries


_PNPM_SLASH = re.compile(r"^\s+/?((?:@[^/\s]+/)?[^/:\s]+)/([^/\s:]+):\s*$")
_PNPM_AT = re.compile(r"^\s+/?((?:@[^/\s]+/)?[^@\s:]+)@([^:(\s]+)(?:\([^)]*\))?:\s*$")


def _pnpm_lock(lines: Sequence[str]) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for line in lines:
        match = _PNPM_AT.match(line) or _PNPM_SLASH.match(line)
        if match:
            entries.append((match.group(1), match.group(2)))
    return entries


_TOML_NAME = re.compile(r'^\s*name\s*=\s*"([^"]+)"')
_TOML_VERSION = re.compile(r'^\s*version\s*=\s*"([^"]+)"')


def _toml_lock(lines: Sequence[str]) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    name = ""
    for line in lines:
        named = _TOML_NAME.match(line)
        if named:
            name = named.group(1)
            continue
        version = _TOML_VERSION.match(line)
        if version and name:
            entries.append((name, version.group(1)))
    return entries


_REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;#]+)")


def _pip_name(name: str) -> str:
    return PEP503_SEPARATORS.sub("-", name).lower()


def _requirements_lock(lines: Sequence[str]) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for line in lines:
        match = _REQUIREMENT.match(line)
        if match:
            entries.append((_pip_name(match.group(1)), match.group(2)))
    return entries


_GO_SUM = re.compile(r"^(\S+)\s+(v[^\s/]+)(?:/go\.mod)?\s+h1:")
_GO_MOD = re.compile(r"^\s*(?:require\s+)?([A-Za-z0-9][A-Za-z0-9._~/-]*)\s+(v[^\s]+)")


def _go_lock(lines: Sequence[str]) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for line in lines:
        text = line.strip()
        match = _GO_SUM.match(text)
        if match:
            entries.append((match.group(1), match.group(2)))
            continue
        if "=>" in text:
            continue
        match = _GO_MOD.match(text)
        if match:
            entries.append((match.group(1), match.group(2)))
    return entries


_USES = re.compile(r"""^\s*(?:-\s+)?uses:\s*["']?([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?:/[^\s@"']*)?@([^\s"']+)""")


def _workflow_uses(lines: Sequence[str]) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for line in lines:
        match = _USES.match(line)
        if match and (pair := (match.group(1), match.group(2).rstrip(","))) not in seen:
            seen.add(pair)
            entries.append(pair)
    return entries


_FORMATS = (
    FileFormat(re.compile(r"(?:^|/)(?:package-lock|npm-shrinkwrap)\.json$"), "npm_and_yarn", _npm_lock),
    FileFormat(re.compile(r"(?:^|/)yarn\.lock$"), "npm_and_yarn", _yarn_lock),
    FileFormat(re.compile(r"(?:^|/)pnpm-lock\.yaml$"), "npm_and_yarn", _pnpm_lock),
    FileFormat(re.compile(r"(?:^|/)poetry\.lock$"), "pip", _toml_lock),
    FileFormat(re.compile(r"(?:^|/)uv\.lock$"), "pip", _toml_lock),
    FileFormat(re.compile(r"(?:^|/)Cargo\.lock$", re.IGNORECASE), "cargo", _toml_lock),
    FileFormat(re.compile(r"(?:^|/)(?:requirements|constraints)[^/]*\.txt$"), "pip", _requirements_lock),
    FileFormat(re.compile(r"(?:^|/)go\.(?:sum|mod)$"), "gomod", _go_lock),
    FileFormat(re.compile(r"^\.github/workflows/[^/]+\.ya?ml$"), "github_actions", _workflow_uses),
)


def _format_for(path: str) -> FileFormat | None:
    return next((file_format for file_format in _FORMATS if file_format.pattern.search(path)), None)


def _version_changes(
    ecosystem: str, old: Iterable[tuple[str, str]], new: Iterable[tuple[str, str]]
) -> list[LockChange]:
    """One change per package whose old and new version sets differ."""
    before: dict[str, set[str]] = {}
    after: dict[str, set[str]] = {}
    for name, version in old:
        if name and version:
            before.setdefault(name, set()).add(version)
    for name, version in new:
        if name and version:
            after.setdefault(name, set()).add(version)
    changes: list[LockChange] = []
    for name in sorted(before.keys() | after.keys()):
        removed = sorted(before.get(name, set()) - after.get(name, set()))
        added = sorted(after.get(name, set()) - before.get(name, set()))
        if len(removed) == 1 and len(added) == 1:
            changes.append(LockChange(ecosystem, name, removed[0], added[0]))
        elif added:
            previous = removed[0] if len(removed) == 1 else ""
            changes.extend(LockChange(ecosystem, name, previous, version) for version in added)
        else:
            changes.extend(LockChange(ecosystem, name, version, "") for version in removed)
    return changes


def changed_packages(text: str) -> tuple[LockChange, ...]:
    """Every lock or manifest package change in the diff, deduplicated."""
    changes: list[LockChange] = []
    for file in parse_diff(text):
        file_format = _format_for(file.path)
        if file_format is None:
            continue
        old = [entry for hunk in file.hunks for entry in file_format.parser(hunk.old)]
        new = [entry for hunk in file.hunks for entry in file_format.parser(hunk.new)]
        changes.extend(_version_changes(file_format.ecosystem, old, new))
    return tuple(dict.fromkeys(changes))


def _name_key(ecosystem: str, name: str) -> str:
    """The comparison form of a package name in one ecosystem."""
    if ecosystem == "gomod":
        return name
    if ecosystem == "pip":
        return _pip_name(name)
    return name.lower()


def missing_from_metadata(
    changes: Iterable[LockChange], updates: Iterable[tuple[str, str, str]]
) -> tuple[LockChange, ...]:
    """Changes whose ecosystem, name and new version are not in the update list."""
    known = {(ecosystem, _name_key(ecosystem, name), version) for ecosystem, name, version in updates}
    missing: list[LockChange] = []
    seen: set[tuple[str, str, str]] = set()
    for change in changes:
        key = (change.ecosystem, _name_key(change.ecosystem, change.name), change.new_version)
        if key not in known and key not in seen:
            seen.add(key)
            missing.append(change)
    return tuple(missing)


def token(text: str, chars: str) -> re.Pattern[str]:
    """A literal match that cannot start or end inside a longer token."""
    return re.compile(rf"(?<![{chars}]){re.escape(text)}(?![{chars}])")


def near(lines: Sequence[str], anchor: str, needle: str, window: int) -> bool:
    """True when `needle` appears within `window` lines of a whole-token `anchor`."""
    anchor_pattern = token(anchor, NAME_CHARS)
    needle_pattern = token(needle, VERSION_CHARS)
    for index, line in enumerate(lines):
        if not anchor_pattern.search(line):
            continue
        nearby = lines[max(0, index - window) : index + window + 1]
        if any(needle_pattern.search(candidate) for candidate in nearby):
            return True
    return False


def near_lines(lines: Sequence[str], anchor: str, window: int) -> list[str]:
    """The lines within `window` of a whole-token `anchor`, in original order."""
    anchor_pattern = token(anchor, NAME_CHARS)
    indexes = {index for index, line in enumerate(lines) if anchor_pattern.search(line)}
    selected: set[int] = set()
    for index in indexes:
        selected.update(range(max(0, index - window), min(len(lines), index + window + 1)))
    return [lines[index] for index in sorted(selected)]


def binding_on_added(binding: str, added: Sequence[str]) -> bool:
    """True when the literal binding appears on an added line."""
    if not binding:
        return False
    pattern = token(binding, BINDING_CHARS)
    return any(pattern.search(line) for line in added)


def locked_hashes(name: str, added: Sequence[str]) -> frozenset[str]:
    """The sha256 values the lock lists near this package's entry."""
    return frozenset(match.group(0) for line in near_lines(added, name, 24) for match in SHA256_VALUE.finditer(line))


def diff_lines(text: str) -> tuple[list[str], list[str]]:
    """The added and removed lines of a diff, without their file headers."""
    lines = text.splitlines()
    return (
        [line[1:] for line in lines if line.startswith("+") and not line.startswith("+++")],
        [line[1:] for line in lines if line.startswith("-") and not line.startswith("---")],
    )


def write_diff(out_dir: Path) -> bool:
    """Write changes.diff and report whether the 2 MiB cap truncated it."""
    (out_dir / "old").mkdir(exist_ok=True)
    (out_dir / "new").mkdir(exist_ok=True)
    try:
        result = subprocess.run(["diff", "-ruN", "old", "new"], cwd=out_dir, check=False, capture_output=True)
    except OSError as exc:
        raise FetchError(f"diff could not run: {exc}") from exc
    if result.returncode not in {0, 1}:
        stderr = result.stderr
        detail = stderr if isinstance(stderr, str) else stderr.decode("utf-8", "replace")
        raise FetchError(f"diff exited {result.returncode}: {detail.strip()[:500]}")
    data = result.stdout
    truncated = len(data) > MAX_DIFF_BYTES
    if truncated:
        data = data[:MAX_DIFF_BYTES] + b"\n[changes.diff truncated at 2 MiB]\n"
    (out_dir / "changes.diff").write_text(data.decode("utf-8", "replace"), encoding="utf-8")
    return truncated


def write_file_list(out_dir: Path) -> list[str]:
    """Write and return every artifact path except the bundle's own outputs."""
    paths = sorted(path.relative_to(out_dir).as_posix() for path in out_dir.rglob("*") if path.is_file())
    paths = [path for path in paths if path not in {"meta.json", "changes.diff", "files.txt"}]
    (out_dir / "files.txt").write_text("\n".join(paths) + ("\n" if paths else ""), encoding="utf-8")
    return paths


def ioc_patterns() -> list[tuple[str, re.Pattern[str]]]:
    """The configured IOC regexes, or a failure when the configuration is not usable."""
    raw = os.environ.get("DEPENDABOT_CURSOR_MALWARE_IOC_PATTERNS", "")
    try:
        patterns = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit("DEPENDABOT_CURSOR_MALWARE_IOC_PATTERNS is not valid JSON") from exc
    if not isinstance(patterns, list) or not patterns or not all(isinstance(p, str) and p for p in patterns):
        raise SystemExit("DEPENDABOT_CURSOR_MALWARE_IOC_PATTERNS must be a non-empty list of non-empty strings")
    try:
        return [(pattern, re.compile(pattern)) for pattern in patterns]
    except re.error as exc:
        raise SystemExit("an IOC pattern is not a valid regex") from exc


def scan_diff(path: Path, patterns: Sequence[tuple[str, re.Pattern[str]]]) -> list[dict[str, object]]:
    """IOC and bidi-control hits on the added lines of a diff file."""
    hits: list[dict[str, object]] = []
    text = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
    for number, line in enumerate(text.splitlines(), 1):
        if not line.startswith("+") or line.startswith("+++"):
            continue
        body = line[1:]
        hits.extend(
            {"kind": "ioc", "pattern": source, "line": number, "match": match.group(0)[:80]}
            for source, pattern in patterns
            if (match := pattern.search(body)) is not None
        )
        if BIDI_CONTROL.search(body) is not None:
            hits.append({"kind": "bidi", "pattern": "bidi-control", "line": number})
    return hits
