"""Manifest and lockfile grammar for a Dependabot diff.

One parser reads each ecosystem. Those entries are the only source for the
changed-package labels and for whether the diff matches the listed update.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

_GO_MOD_RE = re.compile(
    r"^\s*(?:require\s+)?([A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]+)+)\s+(v\S+)",
    re.M,
)
_GO_SUM_RE = re.compile(r"^(\S+)\s+(v\S+)\s+", re.M)
_REQ_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:==|>=|<=|~=|!=|===)\s*([^\s#;]+)",
    re.M,
)
_YARN_HEADER_RE = re.compile(r'"?(@?[^@"\s]+)@[^:]*:')
_YARN_VERSION_RE = re.compile(r'^\s+version\s+"([^"]+)"')
_VERSION_PREFIX_RE = re.compile(r"^(>=|<=|v|\^|~|=|>|<)")
_GO_BLOCK_STARTS = frozenset({"require(", "replace(", "exclude(", "retract("})
_OPAQUE_LOCKS = {
    "pnpm-lock.yaml",
    "Cargo.lock",
    "poetry.lock",
    "Pipfile.lock",
    "Gemfile.lock",
    "composer.lock",
}


def _direct_lock_name(key: str) -> str:
    prefix = "node_modules/"
    if not key.startswith(prefix) or "/node_modules/" in key[len(prefix) :]:
        return ""
    return key[len(prefix) :]


def _go_mod_lines(text: str) -> list[tuple[str, str]]:
    """Classify go.mod lines. Only require lines are entries."""
    classified: list[tuple[str, str]] = []
    block = ""
    for line in text.splitlines(keepends=True):
        compact = "".join(line.split("//", 1)[0].split())
        if block:
            classified.append(("entry" if block == "require" else "residue", line))
            if compact == ")":
                block = ""
            continue
        if compact in _GO_BLOCK_STARTS:
            block = compact[:-1]
            classified.append(("residue", line))
            continue
        if compact.startswith(("replace", "exclude", "retract")):
            classified.append(("residue", line))
            continue
        classified.append(("entry", line))
    return classified


def _manifest_kind(path: str) -> str:
    name = Path(path).name
    lowered = path.replace("\\", "/")
    if name in {"package.json", "package-lock.json", "npm-shrinkwrap.json"}:
        return "json"
    if name == "go.mod":
        return "go.mod"
    if name == "go.sum":
        return "go.sum"
    if name == "yarn.lock":
        return "yarn"
    if name in _OPAQUE_LOCKS:
        return "opaque"
    if (name.startswith("requirements") or "/requirements/" in lowered) and name.endswith(".txt"):
        return "requirements"
    return ""


def _listed_versions(updates: list[dict], *, lower: bool = False) -> dict[str, set[tuple[str, str]]]:
    found: dict[str, set[tuple[str, str]]] = {}
    for item in updates:
        name = str(item.get("packageName") or "").strip()
        if lower:
            name = name.lower()
        if not name:
            continue
        pair = (str(item.get("fromVersion") or "").strip(), str(item.get("toVersion") or "").strip())
        found.setdefault(name, set()).add(pair)
    return found


def _version_body(value: str) -> str:
    match = _VERSION_PREFIX_RE.match(value)
    return value[match.end() :] if match else value


def _reached_listed_version(name: str, old: str, new: str, listed: dict[str, set[tuple[str, str]]]) -> bool:
    """True when this package moved from its listed version to its listed version.

    A leading v is optional. Any other prefix, such as an npm range, must be
    unchanged, and the version text after it must be the listed one.
    """
    if not old or not new or old == new:
        return False
    old_prefix = _VERSION_PREFIX_RE.match(old)
    new_prefix = _VERSION_PREFIX_RE.match(new)
    old_mark = old_prefix.group(1) if old_prefix else ""
    new_mark = new_prefix.group(1) if new_prefix else ""
    if old_mark != new_mark and (old_mark not in {"", "v"} or new_mark not in {"", "v"}):
        return False
    old_body, new_body = _version_body(old), _version_body(new)
    if not old_body or not new_body:
        return False
    return any(_version_body(frm) == old_body and _version_body(to) == new_body for frm, to in listed.get(name, ()))


def _json_entry_version(parts: dict[str, object]) -> str:
    lock = parts.get("lock")
    if isinstance(lock, dict) and lock.get("version"):
        return str(lock["version"])
    spec = parts.get("spec")
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict) and spec.get("version"):
        return str(spec["version"])
    return ""


def _take_specs(block: object, parts: dict[str, dict[str, object]]) -> None:
    if not isinstance(block, dict):
        return
    for name in list(block):
        spec = block[name]
        if isinstance(spec, str):
            parts.setdefault(str(name), {})["spec"] = spec
            del block[name]
            continue
        if not isinstance(spec, dict) or not spec.get("version"):
            continue
        nested = {
            key: spec.pop(key) for key in ("dependencies", "optionalDependencies") if isinstance(spec.get(key), dict)
        }
        parts.setdefault(str(name), {})["spec"] = spec
        if nested:
            block[name] = nested
        else:
            del block[name]


def _json_parts(text: str) -> tuple[dict[str, tuple[str, str]], str] | None:
    if not text.strip():
        return {}, ""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(doc, dict):
        return None
    parts: dict[str, dict[str, object]] = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        _take_specs(doc.get(section), parts)
        block = doc.get(section)
        if isinstance(block, dict) and not block:
            doc.pop(section, None)
    packages = doc.get("packages")
    if isinstance(packages, dict):
        root = packages.get("")
        if isinstance(root, dict):
            for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                _take_specs(root.get(section), parts)
                block = root.get(section)
                if isinstance(block, dict) and not block:
                    root.pop(section, None)
        for key in list(packages):
            if not isinstance(key, str):
                continue
            name = _direct_lock_name(key)
            meta = packages.get(key)
            if not name or not isinstance(meta, dict):
                continue
            parts.setdefault(name, {})["lock"] = meta
            del packages[key]
        if not packages:
            doc.pop("packages", None)
    entries = {
        name: (_json_entry_version(blob), json.dumps(blob, sort_keys=True, separators=(",", ":")))
        for name, blob in parts.items()
    }
    return entries, json.dumps(doc, sort_keys=True, separators=(",", ":"))


def _go_mod_parts(text: str) -> tuple[dict[str, list[tuple[str, str]]], str]:
    entries: dict[str, list[tuple[str, str]]] = {}
    residue: list[str] = []
    for kind, line in _go_mod_lines(text):
        code = line.split("//", 1)[0]
        match = _GO_MOD_RE.match(code) if kind == "entry" else None
        if match:
            entries.setdefault(match.group(1), []).append((match.group(2), code.strip()))
            continue
        residue.append(line)
    return entries, "".join(residue)


def _go_sum_version(tokens: set[str]) -> str:
    primaries = sorted({token.split("/go.mod", 1)[0] for token in tokens})
    return primaries[0] if len(primaries) == 1 else " ".join(primaries)


def _go_sum_parts(text: str) -> tuple[dict[str, tuple[str, str]], str]:
    grouped: dict[str, list[str]] = {}
    versions: dict[str, set[str]] = {}
    residue: list[str] = []
    for line in text.splitlines(keepends=True):
        body = line.strip()
        match = _GO_SUM_RE.match(body)
        if not body or not match:
            residue.append(line)
            continue
        name, version = match.group(1), match.group(2)
        grouped.setdefault(name, []).append(body)
        versions.setdefault(name, set()).add(version)
    entries = {name: (_go_sum_version(versions[name]), "\n".join(sorted(grouped[name]))) for name in grouped}
    return entries, "".join(residue)


def _req_parts(text: str) -> tuple[dict[str, list[tuple[str, str]]], str]:
    entries: dict[str, list[tuple[str, str]]] = {}
    residue: list[str] = []
    for line in text.splitlines(keepends=True):
        match = _REQ_RE.match(line)
        if match:
            entries.setdefault(match.group(1).lower(), []).append((match.group(2), line.strip()))
            continue
        residue.append(line)
    return entries, "".join(residue)


def _yarn_parts(text: str) -> tuple[dict[str, list[tuple[str, str]]], str]:
    entries: dict[str, list[tuple[str, str]]] = {}
    residue: list[str] = []
    names: list[str] = []
    block: list[str] = []
    version = ""

    def flush() -> None:
        nonlocal names, block, version
        if names:
            item = (version, "\n".join(block))
            for name in names:
                entries.setdefault(name, []).append(item)
        elif block:
            residue.append("\n".join(block) + "\n")
        names, block, version = [], [], ""

    for raw in text.splitlines():
        if raw and not raw.startswith((" ", "\t")):
            flush()
            names = _YARN_HEADER_RE.findall(raw)
            block = [raw]
            version = ""
            continue
        block.append(raw)
        match = _YARN_VERSION_RE.match(raw)
        if match:
            version = match.group(1)
    flush()
    return entries, "".join(residue)


def _split_entries(kind: str, text: str) -> tuple[dict[str, tuple[str, str]], str] | None:
    if kind == "json":
        return _json_parts(text)
    if kind == "go.mod":
        return _go_mod_parts(text)
    if kind == "go.sum":
        return _go_sum_parts(text)
    if kind == "requirements":
        return _req_parts(text)
    if kind == "yarn":
        return _yarn_parts(text)
    return None


def _entry_blocks(entry: object) -> list[tuple[str, str]]:
    if isinstance(entry, tuple):
        return [entry]
    if isinstance(entry, list):
        return [item for item in entry if isinstance(item, tuple)]
    return []


def _stanza_versions(blocks: list[tuple[str, str]]) -> dict[str, str] | None:
    found: dict[str, str] = {}
    for version, payload in blocks:
        key = payload.split("\n", 1)[0]
        if not key or key in found:
            return None
        found[key] = version
    return found


def _blocks_explain(
    name: str,
    old_blocks: list[tuple[str, str]],
    new_blocks: list[tuple[str, str]],
    listed: dict[str, set[tuple[str, str]]],
    *,
    keyed: bool,
) -> bool:
    old_left = list(old_blocks)
    new_left = list(new_blocks)
    for block in list(old_left):
        if block in new_left:
            old_left.remove(block)
            new_left.remove(block)
    if not old_left and not new_left:
        return True
    if keyed:
        old_map = _stanza_versions(old_left)
        new_map = _stanza_versions(new_left)
        if old_map is None or new_map is None or set(old_map) != set(new_map):
            return False
        return all(_reached_listed_version(name, old_map[key], new_map[key], listed) for key in old_map)
    if len(old_left) != 1 or len(new_left) != 1:
        return False
    return _reached_listed_version(name, old_left[0][0], new_left[0][0], listed)


def _single_version(entry: object) -> str | None:
    """The version when a name has one entry. Several entries are not one label."""
    blocks = _entry_blocks(entry)
    if len(blocks) > 1:
        return None
    if not blocks:
        return ""
    return blocks[0][0]


def _changed_names(kind: str, before: str, after: str) -> set[str] | None:
    """Names whose one parsed version changed.

    The version is taken from the same entries `_entries_explain` reads.
    A name with more than one entry is not a label. Explain still compares
    every entry, so a duplicate require or pin stays unresolved.
    """
    old_split = _split_entries(kind, before)
    new_split = _split_entries(kind, after)
    if old_split is None or new_split is None:
        return None
    old_entries = old_split[0]
    new_entries = new_split[0]
    changed: set[str] = set()
    for name in set(old_entries) | set(new_entries):
        old_version = _single_version(old_entries.get(name))
        new_version = _single_version(new_entries.get(name))
        if old_version is None or new_version is None or old_version == new_version:
            continue
        changed.add(name)
    return changed


def _entries_explain(kind: str, before: str, after: str, updates: list[dict]) -> bool:
    """True when every changed entry moved to its listed version.

    Checksums on that entry are part of the change. A same-version entry,
    an unlisted package, a replace line, a yarn key that appears or
    disappears, or any other residue is not.
    """
    old_split = _split_entries(kind, before)
    new_split = _split_entries(kind, after)
    if old_split is None or new_split is None:
        return False
    old_entries, old_residue = old_split
    new_entries, new_residue = new_split
    if old_residue != new_residue:
        return False
    listed = _listed_versions(updates, lower=kind == "requirements")
    names = set(old_entries) | set(new_entries)
    return all(
        _blocks_explain(
            name,
            _entry_blocks(old_entries.get(name)),
            _entry_blocks(new_entries.get(name)),
            listed,
            keyed=kind == "yarn",
        )
        for name in names
    )
