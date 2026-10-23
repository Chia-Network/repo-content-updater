"""The one version model: exact-version grammar, npm ranges, release-tag spellings and version jumps.

The manifest parsers, the coverage scan and the upstream scan shell all read
versions here. Each mode names where a token comes from and so which prefix
it may drop and which version shape is exact. A range, wildcard, tag name or
moving major such as an action's `v4` is never an exact version in any mode.

The shell calls the command line. Python itself exits 1 or 2 when the
script fails, so every answer other than success uses its own code above 2:
  dependency_cursor_review_versions.py release-tag REPO VERSION
      prints "<sha>\\t<tag>"; exit 3 when no spelling peels, 4 when spellings disagree
  dependency_cursor_review_versions.py jump FROM TO
      exit 0 when the bump is a version-jump anomaly, 3 when it is not
"""

from __future__ import annotations

import enum
import re
import subprocess
import sys
from dataclasses import dataclass
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
# The three numeric parts of an npm semver, shared by a package.json spec and a registry version.
_SEMVER_RELEASE = r"[0-9]+\.[0-9]+\.[0-9]+"
# `1` or `1.2` is an npm X-range, never an exact pin, so a spec has exactly three numeric parts.
_SPEC_VERSION_RE = re.compile(_SEMVER_RELEASE + _SUFFIX)
# A Dependabot version such as 2024.2 or 1.2.3.4 is exact; a bare `1` or `v4` is a moving major.
_RAW_VERSION_RE = re.compile(r"(?P<release>[0-9]+(?:\.[0-9]+)+)" + _SUFFIX)
# An npm registry version as it appears in a tarball URL or a residue spec. The
# registry writes only npm's own pre-release/build suffix, never a PEP 440 one.
NPM_SEMVER = _SEMVER_RELEASE + r"(?:[-+][0-9A-Za-z.-]+)?"
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


def _exact_match(value: str, *, mode: VersionMode) -> re.Match[str] | None:
    prefix, pattern = _MODES[mode]
    return pattern.fullmatch(_version_body(value, prefix))


def _exact_body(value: str, *, mode: VersionMode = "pin") -> str:
    """The exact version a token pins under `mode`, or "" for a range, wildcard or empty token."""
    match = _exact_match(value, mode=mode)
    return match.group(0) if match else ""


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
        return any(
            _exact_body(frm)
            and _exact_body(to)
            and _exact_body(to) in locked
            and _in_range(old, frm)
            and _in_range(new, to)
            for frm, to in listed.get(name, ())
        )
    old_body, new_body = _exact_body(old, mode=mode), _exact_body(new, mode=mode)
    if not old_body or not new_body:
        return False
    return any(_exact_body(frm) == old_body and _exact_body(to) == new_body for frm, to in listed.get(name, ()))


class TagStatus(enum.IntEnum):
    """How a release-tag lookup ended. The value is the command-line exit code."""

    FOUND = 0
    ABSENT = 3
    DISAGREE = 4


@dataclass(frozen=True)
class ReleaseTag:
    status: TagStatus
    commit: str = ""
    name: str = ""


_ABSENT = ReleaseTag(TagStatus.ABSENT)
_DISAGREE = ReleaseTag(TagStatus.DISAGREE)
# `jump` exits 0 for an anomaly and this code for an ordinary bump.
NO_JUMP = 3


def _tag_name_ok(name: str) -> bool:
    proc = subprocess.run(
        ["git", "check-ref-format", "--allow-onelevel", f"refs/tags/{name}"], capture_output=True, check=False
    )
    return proc.returncode == 0


def _peel(repo: str, name: str) -> str:
    """The commit `refs/tags/<name>` peels to, or "" when it is not a valid, existing tag."""
    if not _tag_name_ok(name):
        return ""
    proc = subprocess.run(
        ["git", "-C", repo, "rev-parse", "--verify", "--quiet", "--end-of-options", f"refs/tags/{name}" + "^{commit}"],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else ""


def release_tag(repo: str, version: str) -> ReleaseTag:
    """The commit and tag name of the release tag for `version` in `repo`.

    One leading `v` or `V` is noted. Every existing spelling of the bare
    version (`<bare>`, `v<bare>`, `V<bare>`) must peel to the same commit.
    A `V` version takes only `V<bare>`; any other version takes `<bare>`,
    then `v<bare>`. DISAGREE means the spellings peel to different commits,
    or a prefixed version would be satisfied only by the other case. ABSENT
    means no accepted spelling peels; branches and raw revisions are not tags.
    """
    lead = version[:1] if version[:1] in {"v", "V"} else ""
    bare = version[len(lead) :]
    if not bare or not _tag_name_ok(bare):
        return _ABSENT
    found = {name: _peel(repo, name) for name in (bare, f"v{bare}", f"V{bare}")}
    if len({commit for commit in found.values() if commit}) > 1:
        return _DISAGREE
    for name in (f"V{bare}",) if lead == "V" else (bare, f"v{bare}"):
        if found[name]:
            return ReleaseTag(TagStatus.FOUND, found[name], name)
    return _DISAGREE if lead and any(found.values()) else _ABSENT


def _major_minor(version: str) -> tuple[int, int] | None:
    """Major and minor of an exact Dependabot version (see _exact_body), or None when it is not one."""
    match = _exact_match(version, mode="dependabot")
    if not match:
        return None
    major, minor = match.group("release").split(".")[:2]
    return int(major), int(minor)


def version_jump(frm: str, to: str) -> bool:
    """True for a major bump, or for more than five minors within one major.

    Both versions are read like the scan's own from/to versions, so an empty
    from version (a scan with no from tag) is never a jump.
    """
    old, new = _major_minor(frm), _major_minor(to)
    if old is None or new is None:
        return False
    return new[0] > old[0] or (new[0] == old[0] and new[1] - old[1] > 5)


def main(argv: list[str]) -> int:
    command, args = argv[:1], argv[1:]
    if command == ["release-tag"] and len(args) == 2:
        found = release_tag(*args)
        if found.status is TagStatus.FOUND:
            print(f"{found.commit}\t{found.name}")
        return found.status.value
    if command == ["jump"] and len(args) == 2:
        return 0 if version_jump(*args) else NO_JUMP
    print("usage: dependency_cursor_review_versions.py release-tag REPO VERSION | jump FROM TO", file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
