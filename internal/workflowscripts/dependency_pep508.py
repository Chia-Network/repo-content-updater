"""A strict PEP 508 requirement parser, from the standard library alone.

parse reads one requirement as pip builds it: a name, optional extras, then a version specifier list or a URL, then
an optional environment marker, and nothing else. It raises ValueError on anything pip would reject, and is
stricter than pip where that is simpler (a malformed version is rejected), so a line it accepts is one pip accepts.
"""

from __future__ import annotations

import re
from typing import NamedTuple

from dependency_cursor_review_versions import PEP440_COMPATIBLE_VERSION, PEP440_LOCAL, PEP440_VERSION

_WS = r"[ \t]*"
_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
# Each operator with the versions it takes: `===` any string up to the next specifier;
# `==` and `!=` a wildcard or a local version; `~=` two release parts; the ranges neither.
_SPEC = (
    rf"(?:===[ \t]*[^\s;),]+"
    rf"|(?:==|!=)[ \t]*{PEP440_VERSION}(?:\.\*|(?:{PEP440_LOCAL})?)"
    rf"|~=[ \t]*{PEP440_COMPATIBLE_VERSION}"
    rf"|(?:<=|>=|<|>)[ \t]*{PEP440_VERSION})"
)
_HEAD_RE = re.compile(
    rf"{_WS}(?P<name>{_NAME}){_WS}(?:\[{_WS}(?:{_NAME}(?:{_WS},{_WS}{_NAME})*)?{_WS}\])?{_WS}", re.IGNORECASE
)
_SPEC_RE = re.compile(rf"{_WS}(?P<spec>{_SPEC}){_WS}", re.IGNORECASE)
_URL_RE = re.compile(rf"@{_WS}[^\s;]+(?:[ \t]+|$)")
_MARKER_VARIABLES = (
    "python_version",
    "python_full_version",
    "os_name",
    "sys_platform",
    "platform_release",
    "platform_system",
    "platform_version",
    "platform_machine",
    "platform_python_implementation",
    "implementation_name",
    "implementation_version",
    "extra",
    "os.name",
    "sys.platform",
    "platform.version",
    "platform.machine",
    "platform.python_implementation",
    "python_implementation",
)
_MARKER_TOKEN_RE = re.compile(
    r"[ \t]*(?:(?P<paren>[()])|(?P<value>'[^']*'|\"[^\"]*\"|(?:"
    + "|".join(re.escape(name) for name in sorted(_MARKER_VARIABLES, key=len, reverse=True))
    + r")(?![\w.]))|(?P<op>===|==|!=|<=|>=|~=|<|>|not[ \t]+in(?!\w)|in(?!\w))|(?P<join>and|or)(?!\w))"
)


class Requirement(NamedTuple):
    name: str
    specs: tuple[tuple[int, int], ...]  # the span of each specifier, operator included


# Deeper groups than any real marker are an error, never a recursion limit.
_MAX_MARKER_DEPTH = 32
_MARKER_SPACE_RE = re.compile(r"[ \t]*")


def _marker(text: str) -> None:
    """Raise ValueError unless text is one marker: comparisons of a variable or string, joined by and/or, grouped."""
    tokens: list[tuple[str, str]] = []
    at = 0
    while (at := _MARKER_SPACE_RE.match(text, at).end()) < len(text):
        match = _MARKER_TOKEN_RE.match(text, at)
        if not match:
            raise ValueError(f"invalid marker at {text[at : at + 40]!r}")
        kind = match.lastgroup or ""
        tokens.append((kind, match.group(kind)))
        at = match.end()

    def expression(index: int, depth: int) -> int:
        """The index after one `and`/`or` chain of atoms starting at index, inside depth groups."""
        index = atom(index, depth)
        while index < len(tokens) and tokens[index][0] == "join":
            index = atom(index + 1, depth)
        return index

    def atom(index: int, depth: int) -> int:
        kinds = [kind for kind, _ in tokens[index : index + 3]]
        if kinds[:1] == ["paren"] and tokens[index][1] == "(":
            if depth == _MAX_MARKER_DEPTH:
                raise ValueError("marker groups nested too deeply")
            index = expression(index + 1, depth + 1)
            if index < len(tokens) and tokens[index] == ("paren", ")"):
                return index + 1
            raise ValueError("unclosed marker group")
        if kinds == ["value", "op", "value"]:
            return index + 3
        raise ValueError("invalid marker comparison")

    if not tokens or expression(0, 0) != len(tokens):
        raise ValueError("invalid marker")


def parse(text: str) -> Requirement:
    """The requirement text holds, or ValueError when pip cannot build one from it."""
    head = _HEAD_RE.match(text)
    if not head:
        raise ValueError("invalid requirement name")
    at, specs = head.end(), []
    if url := _URL_RE.match(text, at):
        at = url.end()
    else:
        grouped = text.startswith("(", at)
        at += grouped
        while spec := _SPEC_RE.match(text, at):
            specs.append(spec.span("spec"))
            at = spec.end()
            if not text.startswith(",", at):
                break
            at += 1
            if not _SPEC_RE.match(text, at):
                raise ValueError("expected a specifier after ','")
        if grouped:
            if not specs or not text.startswith(")", at):
                raise ValueError("unclosed specifier group")
            at = len(text) - len(text[at + 1 :].lstrip(" \t"))
    if text.startswith(";", at):
        _marker(text[at + 1 :])
    elif text[at:].strip(" \t"):
        raise ValueError(f"unexpected {text[at:]!r}")
    return Requirement(head.group("name"), tuple(specs))
