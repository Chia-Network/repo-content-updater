"""The dependency changes of a pull request, read from its manifests and lockfiles.

The diff is the update list. plan() reads each changed path with its row in
the ecosystem table and sorts every version move into one of:

- primary: a declared dependency whose version moved. A lock beside a
  manifest records the installed versions, so a manifest with a parsed lock
  beside it only says which names are declared, and the lock supplies the
  versions; a name the manifest moved must also move in that lock. A primary
  is scanned, or reported by its ecosystem's policy.
- unchecked: every other package whose version moved, such as an undeclared
  or nested lock copy or a go.mod `// indirect` require. Disclosed, not scanned.
- gaps: (path, reason) for a path that is not a dependency file, was deleted
  or changed type, does not parse, or changed in a way its versions do not
  account for: residue outside the entries, an entry whose text changed at an
  unchanged version, or a line entry whose text outside the version changed.
- unparsed_locks: a lockfile with no grammar beside a primary change. With no
  primary change beside it, it is a gap.

A name with several entries compares as a set of versions. old and new are the
versions removed and added, joined with ", ", so a name that moved more than
one copy is never an exact version.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import PurePosixPath
from typing import NamedTuple

import dependency_cursor_review_ecosystems as ecosystems
from dependency_cursor_review_ecosystems import CHECKSUMS, LOCK, MANIFEST, Ecosystem

# (revision, path) -> the file's text, "" when it is absent.
Read = Callable[[str, str], str]


class Change(NamedTuple):
    ecosystem: str
    dir: str
    name: str
    old: str
    new: str


class Plan(NamedTuple):
    primary: tuple[Change, ...]
    unchecked: tuple[Change, ...]
    gaps: tuple[tuple[str, str], ...]
    unparsed_locks: tuple[str, ...]


def _moves(row: ecosystems.FileKind, directory: str, before: list, after: list) -> list[tuple[Change, bool]] | None:
    """Each (name, top) whose set of versions differs, with whether it is the top copy.

    None when an entry changed in a way its versions do not account for.
    """
    sides: dict[tuple[str, bool], tuple[dict[str, set[str]], dict[str, set[str]]]] = {}
    for side, entries in enumerate((before, after)):
        for name, version, top, text in entries:
            sides.setdefault((name, top), ({}, {}))[side].setdefault(version, set()).add(text)
    moved: list[tuple[Change, bool]] = []
    for (name, top), (old, new) in sorted(sides.items()):
        if any(old[version] != new[version] for version in old.keys() & new.keys()):
            return None
        if not row.records and old and new and set().union(*old.values()) != set().union(*new.values()):
            return None
        if old.keys() != new.keys():
            removed, added = ", ".join(sorted(old.keys() - new.keys())), ", ".join(sorted(new.keys() - old.keys()))
            moved.append((Change(row.ecosystem.name, directory, name, removed, added), top))
    return moved


def _file_moves(row: ecosystems.FileKind, old_path: str, path: str, read: Read, base: str) -> list | None:
    """The moves of one changed file with a grammar, or None when a side does not parse or its residue changed."""
    before, after = row.parse(read(base, old_path)), row.parse(read("HEAD", path))
    if before is None or after is None or before[1] != after[1]:
        return None
    return _moves(row, str(PurePosixPath(path).parent), before[0], after[0])


def _declared(ecosystem: Ecosystem, directory: str, read: Read, base: str) -> set[str] | None:
    """Names the manifests beside a lock declare at base or HEAD, or None when none is there or one does not parse."""
    names: set[str] = set()
    found = False
    for path, row in ecosystems.beside(ecosystem, MANIFEST, directory):
        for revision in (base, "HEAD"):
            text = read(revision, path)
            if not text:
                continue
            parsed = row.parse(text)
            if parsed is None:
                return None
            found = True
            names |= {name for name, _version, top, _text in parsed[0] if top}
    return names if found else None


def _has_lock(ecosystem: Ecosystem, directory: str, read: Read) -> bool:
    return any(read("HEAD", path) for path, _row in ecosystems.beside(ecosystem, LOCK, directory))


def plan(changed: list[tuple[str, str, str]], read: Read, base: str) -> Plan:
    """Sort (before path, after path, status letter) for each changed path into a Plan."""
    primary: list[Change] = []
    unchecked: list[Change] = []
    gaps: list[tuple[str, str]] = []
    opaque: list[tuple[str, str, str]] = []
    # Names each manifest moved while a lock beside it supplies the versions, and the top lock copies that moved.
    deferred: list[tuple[str, str, str, set[str]]] = []
    lock_moved: set[tuple[str, str, str]] = set()
    for old_path, path, status in changed:
        row = ecosystems.file_kind(path)
        directory = str(PurePosixPath(path).parent)
        if status in {"D", "T"} or row is None:
            gaps.extend((label, "unresolved") for label in dict.fromkeys((old_path, path)))
            continue
        if row.role == CHECKSUMS:
            continue
        if row.parse is None:
            if row.role == LOCK:
                opaque.append((row.ecosystem.name, directory, path))
            else:
                gaps.append((path, "unparsed_manifest"))
            continue
        moves = _file_moves(row, old_path, path, read, base)
        if moves is None:
            gaps.append((path, "unresolved"))
            continue
        if row.role == MANIFEST and _has_lock(row.ecosystem, directory, read):
            deferred.append((row.ecosystem.name, directory, path, {change.name for change, _top in moves}))
            continue
        declared = _declared(row.ecosystem, directory, read, base) if row.role == LOCK else None
        if row.role == LOCK and declared is None:
            gaps.append((path, "unresolved"))
            continue
        for change, top in moves:
            if top and row.role == LOCK:
                lock_moved.add((change.ecosystem, change.dir, change.name))
            (primary if top and (declared is None or change.name in declared) else unchecked).append(change)
    gaps.extend(
        (path, "unresolved")
        for name, directory, path, names in deferred
        if any((name, directory, moved) not in lock_moved for moved in names)
    )
    beside_primary = {(change.ecosystem, change.dir) for change in primary}
    unparsed_locks = [path for name, directory, path in opaque if (name, directory) in beside_primary]
    gaps.extend((path, "unresolved") for name, directory, path in opaque if (name, directory) not in beside_primary)
    return Plan(
        tuple(dict.fromkeys(primary)),
        tuple(dict.fromkeys(unchecked)),
        tuple(dict.fromkeys(gaps)),
        tuple(dict.fromkeys(unparsed_locks)),
    )
