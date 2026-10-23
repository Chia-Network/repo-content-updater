"""Exact-pin version grammar shared by the manifest parsers.

Only `==`, `===` or one leading `v`/`V` is removed. A range, wildcard or
tag name is never an exact version.
"""

from __future__ import annotations

import re

# Only an exact pin drops its prefix. Every range operator stays on the token.
_PIN_PREFIX_RE = re.compile(r"^(?:===|==|[vV])")
# Dot-separated numeric parts are the version. An x/X or * part is a wildcard,
# never an exact pin, but a -prerelease or +build suffix may spell one out.
_EXACT_VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+)*(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?")


def _version_body(value: str) -> str:
    """The version with one exact-pin prefix (`==`, `===`, `v` or `V`) removed."""
    value = value.strip()
    match = _PIN_PREFIX_RE.match(value)
    return value[match.end() :].strip() if match else value


def _exact_body(value: str) -> str:
    """The exact version a token pins, or "" for a range, wildcard or empty token."""
    body = _version_body(value)
    return body if _EXACT_VERSION_RE.fullmatch(body) else ""


def _reached_listed_version(
    name: str,
    old: str,
    new: str,
    listed: dict[str, set[tuple[str, str]]],
    *,
    locked: frozenset[str] = frozenset(),
) -> bool:
    """True when this package moved from one listed exact version to the other.

    Listed and manifest tokens must both be exact pins. A package.json spec
    may keep the same leading `^` or `~` on both sides only when `locked`,
    the versions a lockfile in HEAD resolves this package to, holds the
    listed `to` version.
    """
    if not old or not new or old == new:
        return False
    if old[:1] in {"^", "~"} and new[:1] == old[:1] and _exact_body(new[1:]) in locked:
        old, new = old[1:], new[1:]
    old_body, new_body = _exact_body(old), _exact_body(new)
    if not old_body or not new_body:
        return False
    return any(_exact_body(frm) == old_body and _exact_body(to) == new_body for frm, to in listed.get(name, ()))
