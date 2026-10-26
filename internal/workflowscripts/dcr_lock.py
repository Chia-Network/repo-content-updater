"""Inspect the PR diff for changed file paths and literal review changes.

The diff text is untrusted data and is never executed. Paths come from the
`diff --git` headers, and the same module owns the literal diff checks, the
diff bundle and its IOC scan.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from collections.abc import Sequence
from pathlib import Path

from dcr_sources import FetchError

MAX_DIFF_BYTES = 2 * 1024 * 1024
BIDI_CONTROL = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")
SHA256_VALUE = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")
NAME_CHARS = r"A-Za-z0-9._~-"
VERSION_CHARS = r"A-Za-z0-9._+-"
BINDING_CHARS = r"A-Za-z0-9._~+/=-"


def _strip_git_prefix(value: str) -> str | None:
    """The path without its a/ or b/ prefix, or None for /dev/null."""
    if value == "/dev/null":
        return None
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    return value[2:] if value.startswith(("a/", "b/")) else value


def _git_paths(line: str) -> tuple[str, ...]:
    """The old and new paths named by one `diff --git` header."""
    rest = line[len("diff --git ") :].strip()
    if '"' in rest:
        try:
            parts = shlex.split(rest)
        except ValueError:
            parts = rest.split()
    else:
        index = rest.find(" b/")
        parts = [rest] if index < 0 else [rest[:index], rest[index + 1 :]]
    return tuple(path for part in parts[:2] if (path := _strip_git_prefix(part)))


def changed_files(text: str) -> tuple[str, ...]:
    """The changed file paths on both sides of the diff's `diff --git` headers."""
    paths: list[str] = []
    for line in text.splitlines():
        if not line.startswith("diff --git "):
            continue
        for path in _git_paths(line):
            if path not in paths:
                paths.append(path)
    return tuple(paths)


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
