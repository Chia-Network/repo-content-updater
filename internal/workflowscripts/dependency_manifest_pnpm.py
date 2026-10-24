"""pnpm-lock.yaml grammar, for lockfile versions 6 and 9.

pnpm_lock returns (entries, residue), or None when the text is not a lock it
reads. An importer's dependency is an entry at the version it installs; the
root importer's are top, like a lock's restated declarations. A `packages` or
`snapshots` stanza is an entry at the version in its key, top when the root
importer installs that version of that name. A version keeps its peer suffix
out, and a stanza whose resolution is anything but a registry integrity keeps
that resolution beside its version, so it is never an exact registry version.

A stanza's text leaves out what other entries account for: the peer suffix of
its key, the versions it resolves its own dependencies to, and the flags that
say which installs include it. A dependency a stanza resolves to a version
that has a stanza is also an entry at that version, so a resolution change no
moved stanza accounts for changes that entry. Residue is every other line,
outside blank lines.
"""

from __future__ import annotations

import json
import re

from dependency_manifest_lines import Entry, Parsed

_VERSIONS = frozenset({"6.0", "6.1", "9.0"})
_MAX_VERSION_LENGTH = 8
_LOCKFILE_VERSION_RE = re.compile(r"""^lockfileVersion: (['"]?)([0-9.]+)\1$""")
_SECTIONS = frozenset({"dependencies", "devDependencies", "optionalDependencies"})
_STANZAS = frozenset({"packages", "snapshots"})
_SCOPE_FLAGS = frozenset({"dev", "optional", "peer", "devOptional"})
_KEY_RE = re.compile(r"""^( *)('[^']+'|"[^"]+"|[^\s'"][^\s]*?):(?: (.*))?$""")
_REGISTRY_RE = re.compile(r"^\{integrity: (\S+)\}$")
_REFERENCE = json.dumps(["dependency reference"])


class _Line:
    def __init__(self, raw: str) -> None:
        match = _KEY_RE.match(raw)
        self.raw, self.indent = raw, len(raw) - len(raw.lstrip(" "))
        self.key = match.group(2).strip("'\"") if match else ""
        self.value = (match.group(3) or "") if match else ""


def _blocks(lines: list[_Line], indent: int) -> list[tuple[_Line, list[_Line]]] | None:
    """Each line at `indent` with the deeper lines under it, or None when a line is shallower or unkeyed."""
    blocks: list[tuple[_Line, list[_Line]]] = []
    for line in lines:
        if line.indent == indent and line.key:
            blocks.append((line, []))
        elif line.indent > indent and blocks:
            blocks[-1][1].append(line)
        else:
            return None
    return blocks


def _name_version(key: str) -> tuple[str, str]:
    """(name, version) of a stanza key such as `/@scope/pkg@1.0.0(peer@2.0.0)`, ("", "") when it has neither."""
    name, _, version = key.removeprefix("/").split("(", 1)[0].rpartition("@")
    return (name, version) if name and version else ("", "")


def _importer(where: str, body: list[_Line], indent: int) -> tuple[list[tuple[str, str, str]], list[str]] | None:
    """(name, version, text) of each dependency under an importer, and its other lines."""
    sections = _blocks(body, indent)
    if sections is None:
        return None
    deps: list[tuple[str, str, str]] = []
    residue: list[str] = []
    for header, lines in sections:
        if header.key not in _SECTIONS or header.value:
            residue += [f"{where}\t{line.raw}" for line in (header, *lines)]
            continue
        blocks = _blocks(lines, indent + 2)
        if blocks is None:
            return None
        for dep, fields in blocks:
            values = {line.key: line.value for line in fields}
            if dep.value or set(values) != {"specifier", "version"} or len(fields) != 2:
                return None
            if any(line.indent != indent + 4 for line in fields):
                return None
            version = values["version"].split("(", 1)[0]
            deps.append((dep.key, version, json.dumps([where, header.key, dep.key, values["specifier"]])))
    return deps, residue


def _stanza_text(kind: str, key: str, body: list[_Line]) -> tuple[str, str, list[tuple[str, str]]]:
    """The text of a packages or snapshots stanza, the resolution its version keeps ("" for the registry), and
    each (name, version) its dependencies resolve to."""
    text: list[str] = []
    resolution = ""
    masking = False
    references: list[tuple[str, str]] = []
    for line in body:
        if line.indent == 4:
            masking = line.key in _SECTIONS and not line.value
            if line.key in _SCOPE_FLAGS:
                continue
            if line.key == "resolution" and not _REGISTRY_RE.match(line.value):
                resolution = line.value
        elif line.indent == 6 and masking:
            references.append((line.key, line.value.split("(", 1)[0].strip()))
            text.append(f"      {line.key}: \0")
            continue
        text.append(line.raw)
    if kind == "packages" and not any(line.indent == 4 and line.key == "resolution" for line in body):
        resolution = "no resolution"
    name, version = _name_version(key)
    return json.dumps([kind, f"{name}@{version}", text]), resolution, references


def _lockfile_version(lines: list[_Line]) -> str:
    """The one top-level lockfileVersion a lock declares, or ""."""
    versions = [
        _LOCKFILE_VERSION_RE.match(line.raw) for line in lines if not line.indent and line.key == "lockfileVersion"
    ]
    return versions[0].group(2) if len(versions) == 1 and versions[0] else ""


def pnpm_lock_unsupported_version(text: str) -> str:
    """The lockfileVersion of a pnpm lock when pnpm_lock does not read that version, or ""."""
    version = _lockfile_version([_Line(raw) for raw in text.splitlines() if raw.strip()])
    return version if version not in _VERSIONS and len(version) <= _MAX_VERSION_LENGTH else ""


def pnpm_lock(text: str) -> Parsed | None:
    lines = [_Line(raw) for raw in text.splitlines() if raw.strip()]
    blocks = _blocks(lines, 0)
    if blocks is None or _lockfile_version(lines) not in _VERSIONS:
        return None
    # A version 6 lock of one project lists its dependency sections at the top level.
    root = [line for header, body in blocks if header.key in _SECTIONS for line in (header, *body)]
    importers: list[tuple[_Line | None, list[_Line], int]] = [(None, root, 0)] if root else []
    stanzas: list[tuple[str, _Line, list[_Line]]] = []
    residue: list[str] = []
    for header, body in blocks:
        children = _blocks(body, 2) if header.key in {"importers", *_STANZAS} and not header.value else []
        if children is None:
            return None
        if header.key in _SECTIONS:
            continue
        if header.key == "importers" and not header.value:
            importers += [(importer, lines, 4) for importer, lines in children]
        elif header.key in _STANZAS and not header.value:
            stanzas += [(header.key, stanza, lines) for stanza, lines in children]
        else:
            residue += [line.raw for line in (header, *body)]
    imports: list[tuple[str, str, bool, str]] = []
    for importer, lines, indent in importers:
        where = importer.key if importer else "."
        if importer and importer.value:
            residue.append(importer.raw)
            continue
        found = _importer(where, lines, indent)
        if found is None:
            return None
        imports += [(name, version, where == ".", text) for name, version, text in found[0]]
        residue += found[1]
    top = {(name, version) for name, version, root_dep, _text in imports if root_dep}
    entries: list[Entry] = list(imports)
    keys = [(kind, stanza.key) for kind, stanza, _lines in stanzas]
    if len(set(keys)) != len(keys):
        return None
    stanza_versions = {_name_version(stanza.key) for _kind, stanza, _lines in stanzas}
    for kind, stanza, lines in stanzas:
        name, version = _name_version(stanza.key)
        if not name or stanza.value not in {"", "{}"} or (stanza.value and lines):
            return None
        stanza_text, resolution, references = _stanza_text(kind, stanza.key, lines)
        entries.append(
            (name, f"{version} ({resolution})" if resolution else version, (name, version) in top, stanza_text)
        )
        entries.extend(
            (ref_name, ref_version, (ref_name, ref_version) in top, _REFERENCE)
            for ref_name, ref_version in references
            if (ref_name, ref_version) in stanza_versions
        )
    return entries, "\n".join(residue)


def pnpm_lock_integrity(text: str) -> str:
    """The registry integrity a pnpm_lock stanza's text records, or "" for any other entry."""
    record = json.loads(text)
    if not (isinstance(record, list) and len(record) == 3 and isinstance(record[2], list)):
        return ""
    for line in record[2]:
        match = _REGISTRY_RE.match(line.strip().removeprefix("resolution: "))
        if line.startswith("    resolution: ") and match:
            return match.group(1)
    return ""
