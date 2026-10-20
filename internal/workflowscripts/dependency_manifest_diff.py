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
# PEP 503: lowercase, and collapse each run of `-`, `_`, or `.` to one `-`.
_PEP503_SEPARATORS = re.compile(r"[-_.]+")


def _direct_lock_name(key: str) -> str:
    """Package name for a lockfile path.

    Nested copies (`node_modules/a/node_modules/b`, and workspace paths such as
    `packages/gui/node_modules/b`) are the leaf package. A path that continues
    past the package name stays in residue.
    """
    marker = "node_modules/"
    index = key.rfind(marker)
    if index < 0:
        return ""
    parts = key[index + len(marker) :].split("/")
    if not parts or not parts[0]:
        return ""
    if parts[0].startswith("@"):
        if len(parts) != 2 or len(parts[0]) < 2 or not parts[1]:
            return ""
        return f"{parts[0]}/{parts[1]}"
    if len(parts) != 1:
        return ""
    return parts[0]


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


def _requirement_name(name: str) -> str:
    """PEP 503 name. Requirements parsing and Dependabot names both use this."""
    return _PEP503_SEPARATORS.sub("-", name).lower()


def _canonical_package_name(kind: str, name: str) -> str:
    if kind == "requirements":
        return _requirement_name(name)
    return name


def _names_listed(kind: str, names: set[str], listed: set[str]) -> bool:
    known = {_canonical_package_name(kind, name) for name in listed}
    return all(_canonical_package_name(kind, name) in known for name in names)


def _listed_versions(updates: list[dict], *, kind: str = "") -> dict[str, set[tuple[str, str]]]:
    found: dict[str, set[tuple[str, str]]] = {}
    for item in updates:
        name = _canonical_package_name(kind, str(item.get("packageName") or "").strip())
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


def _json_blocks(blob: dict[str, object]) -> list[tuple[str, str]]:
    """One block per manifest spec and per lockfile path. Paths do not collapse."""
    blocks: list[tuple[str, str]] = []
    spec = blob.get("spec")
    if isinstance(spec, str):
        blocks.append((spec, json.dumps({"spec": spec}, separators=(",", ":"))))
    elif isinstance(spec, dict):
        blocks.append(
            (str(spec.get("version") or ""), json.dumps({"spec": spec}, sort_keys=True, separators=(",", ":")))
        )
    locks = blob.get("locks")
    if isinstance(locks, list):
        ordered = [item for item in locks if isinstance(item, tuple) and len(item) == 2]
        for path, meta in sorted(ordered, key=lambda item: item[0]):
            if not isinstance(path, str) or not isinstance(meta, dict):
                continue
            body = dict(meta)
            body["path"] = path
            blocks.append((str(meta.get("version") or ""), json.dumps(body, sort_keys=True, separators=(",", ":"))))
    return blocks


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
            locks = parts.setdefault(name, {}).setdefault("locks", [])
            if isinstance(locks, list):
                locks.append((key, meta))
            del packages[key]
        if not packages:
            doc.pop("packages", None)
    entries: dict[str, tuple[str, str] | list[tuple[str, str]]] = {}
    for name, blob in parts.items():
        blocks = _json_blocks(blob)
        if len(blocks) == 1:
            entries[name] = blocks[0]
        elif blocks:
            entries[name] = blocks
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


def _go_sum_version(token: str) -> str:
    """Module version, without the `/go.mod` checksum suffix."""
    return token.split("/go.mod", 1)[0]


def _go_sum_parts(text: str) -> tuple[dict[str, list[tuple[str, str]]], str]:
    """One block per module version. Versions of a module stay a set."""
    grouped: dict[str, dict[str, list[str]]] = {}
    residue: list[str] = []
    for line in text.splitlines(keepends=True):
        body = line.strip()
        match = _GO_SUM_RE.match(body)
        if not body or not match:
            residue.append(line)
            continue
        module, version = match.group(1), _go_sum_version(match.group(2))
        grouped.setdefault(module, {}).setdefault(version, []).append(body)
    entries = {
        module: [(version, "\n".join(sorted(rows))) for version, rows in sorted(by_version.items())]
        for module, by_version in grouped.items()
    }
    return entries, "".join(residue)


def _req_parts(text: str) -> tuple[dict[str, list[tuple[str, str]]], str]:
    entries: dict[str, list[tuple[str, str]]] = {}
    residue: list[str] = []
    for line in text.splitlines(keepends=True):
        match = _REQ_RE.match(line)
        if match:
            entries.setdefault(_requirement_name(match.group(1)), []).append((match.group(2), line.strip()))
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


def _stanza_entries(blocks: list[tuple[str, str]]) -> dict[str, tuple[str, str]] | None:
    found: dict[str, tuple[str, str]] = {}
    for version, payload in blocks:
        key = payload.split("\n", 1)[0]
        if not key or key in found:
            return None
        found[key] = (version, payload)
    return found


def _version_map(blocks: list[tuple[str, str]]) -> dict[str, str] | None:
    found: dict[str, str] = {}
    for version, payload in blocks:
        if version in found:
            return None
        found[version] = payload
    return found


def _version_named(versions: dict[str, str], listed: str) -> str | None:
    body = _version_body(listed)
    if not body:
        return None
    found = [version for version in versions if _version_body(version) == body]
    if len(found) != 1:
        return None
    return found[0]


def _sum_update_covers(old: dict[str, str], new: dict[str, str], frm: str, to: str) -> bool:
    """True when `to` is in the new set and `from` was in the old set.

    Removing `from` matches. Keeping those lines and adding `to` matches.
    A checksum rewrite of any version that stays does not.
    """
    to_key = _version_named(new, to)
    from_key = _version_named(old, frm)
    if to_key is None or from_key is None or _version_body(from_key) == _version_body(to_key):
        return False
    removed = set(old) - set(new)
    added = set(new) - set(old)
    if removed - {from_key} or added - {to_key}:
        return False
    stayed = set(old) & set(new)
    if any(old[key] != new[key] for key in stayed):
        return False
    return bool(removed or added)


def _go_sum_explained(
    name: str,
    old_blocks: list[tuple[str, str]],
    new_blocks: list[tuple[str, str]],
    listed: dict[str, set[tuple[str, str]]],
) -> bool:
    old = _version_map(old_blocks)
    new = _version_map(new_blocks)
    if old is None or new is None:
        return False
    if old == new:
        return True
    return any(_sum_update_covers(old, new, frm, to) for frm, to in listed.get(name, ()))


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
        old_map = _stanza_entries(old_left)
        new_map = _stanza_entries(new_left)
        if old_map is None or new_map is None or set(old_map) != set(new_map):
            return False
        return all(_pair_explained(name, old_map[key], new_map[key], listed) for key in old_map)
    pairs = _pair_blocks(old_left, new_left)
    if pairs is None:
        return False
    return all(_pair_explained(name, old, new, listed) for old, new in pairs)


def _name_explained(
    kind: str,
    name: str,
    old_blocks: list[tuple[str, str]],
    new_blocks: list[tuple[str, str]],
    listed: dict[str, set[tuple[str, str]]],
) -> bool:
    if kind == "go.sum":
        return _go_sum_explained(name, old_blocks, new_blocks, listed)
    return _blocks_explain(name, old_blocks, new_blocks, listed, keyed=kind == "yarn")


def _single_version(entry: object) -> str | None:
    """The version when a name has one entry. Several entries are not one label."""
    blocks = _entry_blocks(entry)
    if len(blocks) > 1:
        return None
    if not blocks:
        return ""
    return blocks[0][0]


_TARBALL_RE = re.compile(
    r"^https://registry\.(?:npmjs\.org|yarnpkg\.com)/"
    r"(?:(?P<scope>@[^/]+)/)?(?P<name>[^/]+)/-/(?P<base>[^/]+)-(?P<version>.+)\.tgz$"
)
_NPM_RESOLUTION_RE = re.compile(r"^(@?[^@\s]+)@npm:(.+)$")
_YARN_VERSION_LINE = re.compile(r'^\s*version:?\s+"?([^"\s]+)"?')
_YARN_RESOLVED_LINE = re.compile(r'^\s*resolved:?\s+"?([^"\s]+)')
_YARN_RESOLUTION_LINE = re.compile(r'^\s*resolution:?\s+"?([^"\s]+)')
_YARN_DROP_LINE = re.compile(r"^\s*(?:integrity|checksum)\b", re.I)
_SPEC_PREFIX_RE = re.compile(r"^[~^=vV](\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$")
_EXACT_VERSION_RE = re.compile(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?")
_SPEC_SECTIONS = frozenset({"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"})


def _canonical_tarball(url: str, version: str, package: str) -> bool:
    """True when `url` is the npm or Yarn registry tarball for this package version."""
    if not url or not version or not package:
        return False
    match = _TARBALL_RE.fullmatch(url.split("#", 1)[0])
    if not match or match.group("version") != version or match.group("base") != match.group("name"):
        return False
    scope = match.group("scope")
    found = f"{scope}/{match.group('name')}" if scope else match.group("name")
    return found == package


def _npm_resolution(value: str, package: str, version: str) -> bool:
    match = _NPM_RESOLUTION_RE.fullmatch(value.strip().strip('"'))
    if not match or match.group(1) != package:
        return False
    return _version_body(match.group(2)) == _version_body(version)


def _normalize_spec_text(value: str) -> str:
    """Keep the range operator and replace an exact version body. Other text stays."""
    prefix = _VERSION_PREFIX_RE.match(value)
    mark = prefix.group(1) if prefix else ""
    body = value[len(mark) :]
    if _EXACT_VERSION_RE.fullmatch(body):
        return mark + "#"
    return value


def _strip_lock_object(node: dict[str, object], package: str) -> dict[str, object]:
    version = node.get("version") if isinstance(node.get("version"), str) else ""
    stripped: dict[str, object] = {}
    for key, value in node.items():
        if key in {"version", "integrity", "checksum"}:
            continue
        if key == "resolved" and isinstance(value, str) and _canonical_tarball(value, version, package):
            continue
        if key == "resolution" and isinstance(value, str) and _npm_resolution(value, package, version):
            continue
        stripped[key] = value
    return stripped


def _without_version(payload: str) -> str:
    """Entry text without install locators.

    A registry tarball URL, an integrity or checksum, and a Yarn `resolution`
    for this package version are locators. Any other resolved URL stays, so a
    swapped host still fails the comparison. Nested dependency objects are
    not locators.
    """
    try:
        doc = json.loads(payload)
    except json.JSONDecodeError:
        return _without_version_text(payload)
    if isinstance(doc, dict):
        doc = _strip_json_locators(doc)
    return json.dumps(doc, sort_keys=True, separators=(",", ":"))


def _strip_json_locators(node: dict[str, object]) -> dict[str, object]:
    spec = node.get("spec")
    path = node.get("path") if isinstance(node.get("path"), str) else ""
    package = _direct_lock_name(path) if path else ""
    if isinstance(spec, str) and "path" not in node:
        return {"spec": _normalize_spec_text(spec)}
    if isinstance(spec, dict) and "path" not in node:
        return {"spec": _strip_lock_object(spec, package)}
    return _strip_lock_object(node, package)


def _without_version_text(payload: str) -> str:
    header = payload.split("\n", 1)[0]
    names = _YARN_HEADER_RE.findall(header)
    package = names[0] if len(names) == 1 else ""
    version = ""
    for line in payload.splitlines():
        match = _YARN_VERSION_LINE.match(line)
        if match:
            version = match.group(1)
            break
    kept: list[str] = []
    for line in payload.splitlines():
        if _YARN_VERSION_LINE.match(line) or _YARN_DROP_LINE.match(line):
            continue
        resolved = _YARN_RESOLVED_LINE.match(line)
        if resolved:
            if not _canonical_tarball(resolved.group(1), version, package):
                kept.append(line)
            continue
        resolution = _YARN_RESOLUTION_LINE.match(line)
        if resolution:
            if not _npm_resolution(resolution.group(1), package, version):
                kept.append(line)
            continue
        kept.append(line)
    return "\n".join(kept)


def _payload_id(payload: str) -> str:
    try:
        doc = json.loads(payload)
    except json.JSONDecodeError:
        return ""
    if not isinstance(doc, dict):
        return ""
    path = doc.get("path")
    if isinstance(path, str) and path:
        return "path:" + path
    if "spec" in doc:
        return "spec"
    return ""


def _pair_blocks(
    old: list[tuple[str, str]], new: list[tuple[str, str]]
) -> list[tuple[tuple[str, str], tuple[str, str]]] | None:
    """Pair lock paths. One unkeyed block pairs with one. Added or ambiguous paths do not."""
    if len(old) == 1 and len(new) == 1 and not _payload_id(old[0][1]) and not _payload_id(new[0][1]):
        return [(old[0], new[0])]
    old_ids = [_payload_id(block[1]) for block in old]
    new_ids = [_payload_id(block[1]) for block in new]
    if not all(old_ids) or not all(new_ids):
        return None
    if len(set(old_ids)) != len(old_ids) or len(set(new_ids)) != len(new_ids) or set(old_ids) != set(new_ids):
        return None
    new_by_id = dict(zip(new_ids, new))
    return [(block, new_by_id[key]) for key, block in zip(old_ids, old)]


def _equivalent_spec(value: str) -> str:
    match = _SPEC_PREFIX_RE.fullmatch(value)
    return match.group(1) if match else value


def _normalize_residue(node: object) -> object:
    """Dependency specs that spell the same version (`^1.2.3` and `1.2.3`) compare equal."""
    if isinstance(node, dict):
        normalized: dict[str, object] = {}
        for key, value in node.items():
            if key in _SPEC_SECTIONS and isinstance(value, dict):
                normalized[key] = {
                    dep: _equivalent_spec(spec) if isinstance(spec, str) else _normalize_residue(spec)
                    for dep, spec in value.items()
                }
                continue
            normalized[key] = _normalize_residue(value)
        return normalized
    if isinstance(node, list):
        return [_normalize_residue(item) for item in node]
    return node


def _residues_match(kind: str, old: str, new: str) -> bool:
    if old == new:
        return True
    if kind != "json":
        return False
    try:
        old_doc = json.loads(old)
        new_doc = json.loads(new)
    except json.JSONDecodeError:
        return False
    old_norm = json.dumps(_normalize_residue(old_doc), sort_keys=True, separators=(",", ":"))
    new_norm = json.dumps(_normalize_residue(new_doc), sort_keys=True, separators=(",", ":"))
    return old_norm == new_norm


def _lock_doc(doc: object) -> bool:
    if not isinstance(doc, dict):
        return False
    if "path" in doc or "lock" in doc:
        return True
    if any(key in doc for key in ("integrity", "resolved", "checksum")):
        return True
    spec = doc.get("spec")
    return isinstance(spec, dict) and any(key in spec for key in ("integrity", "resolved", "checksum"))


def _lock_text(payloads: list[str]) -> bool:
    """Yarn stanza text. A module or requirement line keeps its version in the entry label."""
    return any(
        re.search(r"(?m)^\s*(?:version|resolved|integrity|checksum|resolution)\b", payload) for payload in payloads
    )


def _payload_ok(old_blocks: list[tuple[str, str]], new_blocks: list[tuple[str, str]]) -> bool:
    """A lock entry may change its version and registry locators. A manifest spec is not a lock payload."""
    payloads = [payload for _version, payload in (*old_blocks, *new_blocks)]
    parsed: list[object] = []
    for payload in payloads:
        try:
            parsed.append(json.loads(payload))
        except json.JSONDecodeError:
            return _version_bump(old_blocks, new_blocks) if _lock_text(payloads) else True
    if any(_lock_doc(doc) for doc in parsed):
        return _version_bump(old_blocks, new_blocks)
    return True


def _version_bump(old_blocks: list[tuple[str, str]], new_blocks: list[tuple[str, str]]) -> bool:
    """True when each paired entry matches, or changes only its version and registry locators."""
    if old_blocks == new_blocks:
        return True
    pairs = _pair_blocks(old_blocks, new_blocks)
    if pairs is None:
        return False
    for old, new in pairs:
        if old == new:
            continue
        if old[0] == new[0] or _without_version(old[1]) != _without_version(new[1]):
            return False
    return True


def _pair_explained(
    name: str,
    old: tuple[str, str],
    new: tuple[str, str],
    listed: dict[str, set[tuple[str, str]]],
) -> bool:
    if not _reached_listed_version(name, old[0], new[0], listed):
        return False
    if _payload_ok([old], [new]):
        return True
    # A listed release may replace registry description fields. The tarball URL may not.
    return name in listed and _release_metadata_ok(name, old, new)


_RELEASE_META = frozenset(
    {
        "bin",
        "bundleDependencies",
        "cpu",
        "dependencies",
        "deprecated",
        "dev",
        "devDependencies",
        "engines",
        "funding",
        "hasInstallScript",
        "inBundle",
        "license",
        "optional",
        "optionalDependencies",
        "os",
        "peerDependencies",
        "peerDependenciesMeta",
    }
)


def _resolved_fields_ok(package: str, payload: str, version: str) -> bool:
    try:
        doc = json.loads(payload)
    except json.JSONDecodeError:
        return False
    if isinstance(doc, dict) and isinstance(doc.get("spec"), dict):
        doc = doc["spec"]
    if not isinstance(doc, dict):
        return False
    path = doc.get("path")
    if isinstance(path, str) and path and _direct_lock_name(path) != package:
        return False
    resolved = doc.get("resolved")
    if isinstance(resolved, str) and not _canonical_tarball(resolved, version, package):
        return False
    resolution = doc.get("resolution")
    if isinstance(resolution, str) and not _npm_resolution(resolution, package, version):
        return False
    return True


def _embedded_lock(value: object) -> bool:
    return isinstance(value, dict) and any(key in value for key in ("integrity", "resolved", "version"))


def _embedded_map_ok(old: dict[str, object], new: dict[str, object]) -> bool:
    """Embedded lockfile v1 records are other installs. A same-version hash swap is not metadata."""
    for key in set(old) | set(new):
        before, after = old.get(key), new.get(key)
        if before == after:
            continue
        if not isinstance(before, dict) or not isinstance(after, dict):
            return False
        if str(before.get("version") or "") == str(after.get("version") or ""):
            return False
        if _without_version(json.dumps(before)) != _without_version(json.dumps(after)):
            return False
    return True


def _spec_text(value: object) -> bool:
    """A version range. A URL or other install locator is not a range."""
    if not isinstance(value, str) or not value or "://" in value or any(char.isspace() for char in value):
        return False
    prefix = _VERSION_PREFIX_RE.match(value)
    body = value[prefix.end() :] if prefix else value
    return _EXACT_VERSION_RE.fullmatch(body) is not None


def _dependency_change_ok(old: object, new: object) -> bool:
    """Listed dependency ranges may move. An embedded lock or a URL may not."""
    old_map = old if isinstance(old, dict) else {}
    new_map = new if isinstance(new, dict) else {}
    if not isinstance(new_map, dict) or (old is not None and not isinstance(old, dict)):
        return False
    if any(_embedded_lock(value) for value in (*old_map.values(), *new_map.values())):
        return _embedded_map_ok(old_map, new_map)
    for key in set(old_map) | set(new_map):
        before, after = old_map.get(key), new_map.get(key)
        if before == after:
            continue
        if not _spec_text(after) or (before is not None and not _spec_text(before)):
            return False
    return True


def _meta_change_ok(old: object, new: object) -> bool:
    if isinstance(old, dict) or isinstance(new, dict):
        old_map = old if isinstance(old, dict) else {}
        new_map = new if isinstance(new, dict) else {}
        if not isinstance(old_map, dict) or not isinstance(new_map, dict):
            return False
        embedded = any(_embedded_lock(value) for value in (*old_map.values(), *new_map.values()))
        return _embedded_map_ok(old_map, new_map) if embedded else True
    return not isinstance(old, list) and not isinstance(new, list)


def _release_metadata_ok(package: str, old: tuple[str, str], new: tuple[str, str]) -> bool:
    if not _resolved_fields_ok(package, old[1], old[0]) or not _resolved_fields_ok(package, new[1], new[0]):
        return False
    try:
        old_doc = json.loads(_without_version(old[1]))
        new_doc = json.loads(_without_version(new[1]))
    except json.JSONDecodeError:
        return False
    if isinstance(old_doc, dict) and isinstance(old_doc.get("spec"), dict):
        old_doc = old_doc["spec"]
    if isinstance(new_doc, dict) and isinstance(new_doc.get("spec"), dict):
        new_doc = new_doc["spec"]
    if not isinstance(old_doc, dict) or not isinstance(new_doc, dict):
        return False
    for key in set(old_doc) | set(new_doc):
        if old_doc.get(key) == new_doc.get(key):
            continue
        if key in _SPEC_SECTIONS:
            if not _dependency_change_ok(old_doc.get(key), new_doc.get(key)):
                return False
            continue
        if key not in _RELEASE_META or not _meta_change_ok(old_doc.get(key), new_doc.get(key)):
            return False
    return True


def _lock_covers_listed(kind: str, before: str, after: str, updates: list[dict], names: set[str]) -> bool:
    """True when a listed package moves to its listed version.

    A listed name must be explained. Every other name may change only its
    version and registry locators. Another resolved host, a same-version
    hash swap, leftover bytes, or a lock that never moves a listed package
    stays unresolved.
    """
    listed = _listed_versions(updates, kind=kind)
    old_split = _split_entries(kind, before)
    new_split = _split_entries(kind, after)
    if old_split is None or new_split is None:
        return False
    old_entries, old_residue = old_split
    new_entries, new_residue = new_split
    listed_moved = any(
        _canonical_package_name(kind, name) in listed
        and _entry_blocks(old_entries.get(name)) != _entry_blocks(new_entries.get(name))
        for name in set(old_entries) | set(new_entries)
    )
    named = any(_canonical_package_name(kind, name) in listed for name in names)
    if not listed_moved and not named:
        return False
    if not _residues_match(kind, old_residue, new_residue):
        return False
    for name in set(old_entries) | set(new_entries):
        old_blocks = _entry_blocks(old_entries.get(name))
        new_blocks = _entry_blocks(new_entries.get(name))
        if _canonical_package_name(kind, name) in listed:
            if not _name_explained(kind, name, old_blocks, new_blocks, listed):
                return False
            continue
        if not _version_bump(old_blocks, new_blocks):
            return False
    return True


def _changed_names(kind: str, before: str, after: str) -> set[str] | None:
    """Names whose one parsed version changed.

    Versions come from the same entries `_entries_explain` reads.
    A name with more than one entry is reported by `_multi_entry_names`.
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


def _multi_entry_names(kind: str, before: str, after: str, updates: list[dict]) -> set[str]:
    """Multi-entry names whose own blocks are not the listed change.

    Several Yarn descriptors for one package are normal. They are a gap
    only when those blocks are unexplained. An unchanged set is not.
    """
    old_split = _split_entries(kind, before)
    new_split = _split_entries(kind, after)
    if old_split is None or new_split is None:
        return set()
    old_entries = old_split[0]
    new_entries = new_split[0]
    listed = _listed_versions(updates, kind=kind)
    found: set[str] = set()
    for name in set(old_entries) | set(new_entries):
        old_blocks = _entry_blocks(old_entries.get(name))
        new_blocks = _entry_blocks(new_entries.get(name))
        if len(old_blocks) <= 1 and len(new_blocks) <= 1:
            continue
        if _name_explained(kind, name, old_blocks, new_blocks, listed):
            continue
        found.add(name)
    return found


def _entries_explain(kind: str, before: str, after: str, updates: list[dict]) -> bool:
    """True when every changed entry moved to its listed version.

    A lock entry is explained when it moves to the listed version and the
    rest is unchanged aside from registry locators. A same-version entry,
    an unlisted package, a replace line, a yarn key that appears or
    disappears, or any other residue is not.

    go.sum keeps one block per version. The listed bump matches when `to`
    is present and `from` was present before, including when `from` was removed.
    """
    old_split = _split_entries(kind, before)
    new_split = _split_entries(kind, after)
    if old_split is None or new_split is None:
        return False
    old_entries, old_residue = old_split
    new_entries, new_residue = new_split
    if not _residues_match(kind, old_residue, new_residue):
        return False
    listed = _listed_versions(updates, kind=kind)
    names = set(old_entries) | set(new_entries)
    return all(
        _name_explained(
            kind,
            name,
            _entry_blocks(old_entries.get(name)),
            _entry_blocks(new_entries.get(name)),
            listed,
        )
        for name in names
    )
