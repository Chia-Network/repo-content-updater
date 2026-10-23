"""Exact-version grammar shared by the manifest parsers and the coverage scan.

Each mode names where a token comes from and so which prefix it may drop
and which version shape is exact. A range, wildcard or tag name is never an
exact version in any mode.
"""

from __future__ import annotations

import re
from typing import Literal

# A PEP 440 pre/post/dev release (`1.2.3rc1`, `1.2.3.post1`, `1.2.3.dev0`)
# or a separator-prefixed pre/build suffix may spell out an exact version.
_SUFFIX = (
    r"(?:"
    r"(?:a|b|c|rc)[0-9]+(?:\.post[0-9]+)?(?:\.dev[0-9]+)?"
    r"|\.post[0-9]+(?:\.dev[0-9]+)?"
    r"|\.dev[0-9]+"
    r"|[-+][0-9A-Za-z][0-9A-Za-z.-]*"
    r")?"
)
# `==` and `===` are Python exact-pin operators; every range operator stays on the token.
_PIN_PREFIX_RE = re.compile(r"^(?:===|==|[vV])")
# Outside a Python manifest only a tag-style `v`/`V` is dropped.
_V_PREFIX_RE = re.compile(r"^[vV]")
# Dot-separated numeric parts are the version. An x/X or * part is a wildcard.
_EXACT_VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+)*" + _SUFFIX)
# `1` or `1.2` is an npm X-range, never an exact pin, so a spec has exactly three numeric parts.
_SPEC_VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+" + _SUFFIX)
# A Dependabot version such as 2024.2 or 1.2.3.4 is exact; a bare `1` or `v4` is a moving major.
_RAW_VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+)+" + _SUFFIX)
# An npm semver: up to three numeric release parts, an optional prerelease and build metadata.
_RANGE_VERSION_RE = re.compile(
    r"(?P<release>[0-9]+(?:\.[0-9]+){0,2})(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?"
)

# pin: a manifest or lock token; drops `==`, `===`, `v` or `V`.
# spec: a package.json spec; drops only `v`/`V` and needs three numeric parts.
# dependabot: a raw Dependabot from/to version; drops only `v`/`V` and needs two or more numeric parts.
VersionMode = Literal["pin", "spec", "dependabot"]
_MODES: dict[str, tuple[re.Pattern[str], re.Pattern[str]]] = {
    "pin": (_PIN_PREFIX_RE, _EXACT_VERSION_RE),
    "spec": (_V_PREFIX_RE, _SPEC_VERSION_RE),
    "dependabot": (_V_PREFIX_RE, _RAW_VERSION_RE),
}


def _version_body(value: str, prefix: re.Pattern[str] = _PIN_PREFIX_RE) -> str:
    """The version with one exact-pin prefix (`==`, `===`, `v` or `V` by default) removed."""
    value = value.strip()
    match = prefix.match(value)
    return value[match.end() :].strip() if match else value


def _exact_body(value: str, *, mode: VersionMode = "pin") -> str:
    """The exact version a token pins under `mode`, or "" for a range, wildcard or empty token."""
    prefix, pattern = _MODES[mode]
    body = _version_body(value, prefix)
    return body if pattern.fullmatch(body) else ""


def _range_key(value: str) -> tuple[tuple[tuple[int, int, int], int, tuple], int] | None:
    """Compare key and release-part count for an npm semver, or None when it is not one."""
    match = _RANGE_VERSION_RE.fullmatch(_version_body(value, _V_PREFIX_RE))
    if not match:
        return None
    parts = tuple(int(part) for part in match.group("release").split("."))
    release = (*parts, 0, 0, 0)[:3]
    pre = match.group("pre")
    if pre is None:
        key = (release, 1, ())
    else:
        identifiers = tuple((0, int(part)) if part.isdigit() else (1, part) for part in pre.split("."))
        key = (release, 0, identifiers)
    return key, len(parts)


def _in_range(spec: str, version: str) -> bool:
    """True when `version` is inside the npm `^` or `~` range `spec`, including 0.x caret rules."""
    operator = spec[:1]
    if operator not in {"^", "~"}:
        return False
    base = _range_key(spec[1:])
    target = _range_key(version)
    if base is None or target is None:
        return False
    (release, _, prerelease), count = base
    target_key = target[0]
    if target_key[1] == 0 and not (prerelease and target_key[0] == release):
        return False
    if operator == "^":
        if release[0]:
            upper = (release[0] + 1, 0, 0)
        elif count == 1:
            upper = (1, 0, 0)
        elif release[1]:
            upper = (0, release[1] + 1, 0)
        elif count == 2:
            upper = (0, 1, 0)
        else:
            upper = (0, 0, release[2] + 1)
    elif count == 1:
        upper = (release[0] + 1, 0, 0)
    else:
        upper = (release[0], release[1] + 1, 0)
    return base[0] <= target_key < (upper, 1, ())


def _reached_listed_version(
    name: str,
    old: str,
    new: str,
    listed: dict[str, set[tuple[str, str]]],
    *,
    locked: frozenset[str] = frozenset(),
    mode: VersionMode = "pin",
) -> bool:
    """True when this package moved from one listed exact version to the other.

    Listed tokens must be exact and `mode` reads the manifest tokens (see
    _exact_body). A package.json spec may keep the same leading `^` or `~` on
    both sides only when `locked`, the versions a lockfile in HEAD resolves the
    new spec to, holds the listed `to` version. The listed `from` version only
    needs to fall inside the old range. Only a top-level `node_modules/<name>`
    npm copy or a Yarn stanza whose descriptor is that exact spec lands in
    `locked`, so a nested, workspace or other-range resolution never confirms a bump.
    """
    if not old or not new or old == new:
        return False
    if old[:1] in {"^", "~"} and new[:1] == old[:1]:
        new_body = _exact_body(new[1:], mode=mode)
        if not new_body or new_body not in locked:
            return False
        return any(
            _exact_body(frm) and _exact_body(to) and _in_range(old, frm) and _in_range(new, to)
            for frm, to in listed.get(name, ())
        )
    old_body, new_body = _exact_body(old, mode=mode), _exact_body(new, mode=mode)
    if not old_body or not new_body:
        return False
    return any(_exact_body(frm) == old_body and _exact_body(to) == new_body for frm, to in listed.get(name, ()))
