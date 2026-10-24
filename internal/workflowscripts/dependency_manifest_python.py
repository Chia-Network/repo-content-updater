"""requirements, pyproject, setup.py, setup.cfg, Pipfile, poetry.lock and Pipfile.lock grammar.

requirements returns (entries, residue). An entry is (PEP 503 name, version
token, top, text); every declared requirement is top. The token keeps its
operator, so `==1.2.3` is exact and `>=1.2` is a range. text is the line with
each of its version tokens masked, so the rest of the line cannot change unseen.
requirements_txt reads a requirements file the way pip does: a line ending in
a backslash continues on the next, and the joined line is one entry, whose
text keeps its `--hash` options. requirements_hashes reads those hashes, and
requirements_line is the text without them, the part that may not change with
the version (the hashes are the version's files, so they change with it).

poetry_lock and pipfile_lock return (entries, residue), or None when the text
does not parse. Every locked package is installed at the top of the
environment, so every entry is top; its text is its whole record, and
residue is the document left once the records and the manifest's content hash
are taken out (the manifest beside the lock is read on its own). A package
locked from anywhere but the package index keeps its version with the source
appended, so it is never read as an exact PyPI version. poetry_lock_hashes and
pipfile_lock_hashes read the file hashes a record locks. A lock from Poetry
before 1.2 keeps each package's files in `[metadata.files]`; each package's
table there joins its record, so it changes with the version.
"""

from __future__ import annotations

import json
import re

import tomllib
from dependency_manifest_lines import Entry, Parsed

_REQ_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*((?:===|==|~=|!=|>=|<=|>|<)\s*[^\s#;,]+)")
# A TOML table header, and a `name = "spec"` or `name = { version = "spec" }` dependency line.
_TOML_TABLE_RE = re.compile(r"^\s*\[+\s*([^\]]+?)\s*\]+\s*$")
_TOML_DEP_RE = re.compile(
    r'^\s*"?([A-Za-z0-9][A-Za-z0-9._-]*)"?\s*=\s*(?:\{[^}]*?\bversion\s*=\s*)?["\']([^"\']+)["\']'
)
_QUOTED_RE = re.compile(r'["\']([^"\']+)["\']')
# pip's comment, and one `--hash=<algorithm>:<digest>` (or `--hash <algorithm>:<digest>`) option of a requirement.
_COMMENT_RE = re.compile(r"(^|\s+)#.*$")
_HASH_RE = re.compile(r"\s+--hash(?:=|\s+)(\S+)")
# PEP 503: lowercase, and collapse each run of `-`, `_`, or `.` to one `-`.
_PEP503_SEPARATORS = re.compile(r"[-_.]+")


def _requirement_name(name: str) -> str:
    return _PEP503_SEPARATORS.sub("-", name).lower()


def _requirement_specs(line: str, table: str) -> list[tuple[str, str]]:
    """(name, version) pairs on one requirements, setup or TOML line.

    A pinned PEP 508 line, or each quoted PEP 508 string when every quoted
    string on the line is one, is an entry. Inside a Poetry or Pipfile
    dependency table a `name = "spec"` line is one as well.
    """
    if table.endswith("dependencies") or table in {"packages", "dev-packages"}:
        match = _TOML_DEP_RE.match(line)
        if match and match.group(1).lower() != "python":
            return [(match.group(1), match.group(2))]
    whole = _REQ_RE.match(line.strip())
    candidates = [whole] if whole else [_REQ_RE.match(text.strip()) for text in _QUOTED_RE.findall(line)]
    # A quoted string that is not a pinned requirement keeps the whole line in residue.
    if not all(candidates):
        return []
    return [(match.group(1), match.group(2)) for match in candidates if match]


def _requirement_lines(lines: list[tuple[str, str]]) -> Parsed:
    """(entries, residue) of (line as read, its text in the file) pairs."""
    entries: list[Entry] = []
    residue: list[str] = []
    table = ""
    for line, original in lines:
        header = _TOML_TABLE_RE.match(line)
        table = header.group(1) if header else table
        found = _requirement_specs(line, table)
        masked = line.strip()
        for _name, version in found:
            masked = masked.replace(version, "\0", 1)
        entries.extend((_requirement_name(name), version, True, masked) for name, version in found)
        if not found:
            residue.append(original)
    return entries, "".join(residue)


def requirements(text: str) -> Parsed:
    return _requirement_lines([(line, line) for line in text.splitlines(keepends=True)])


def requirements_txt(text: str) -> Parsed:
    """requirements, with each backslash-continued line joined to the next as pip joins them.

    pip ends a continuation at a line that holds a comment, and drops each joining backslash and line break.
    """
    lines: list[tuple[str, str]] = []
    joined = original = ""
    for line in text.splitlines(keepends=True):
        bare = line.rstrip("\r\n")
        original += line
        if bare.endswith("\\") and not _COMMENT_RE.search(bare):
            joined += bare[:-1]
            continue
        lines.append((joined + line, original))
        joined = original = ""
    if original:
        lines.append((joined, original))
    return _requirement_lines(lines)


def _code(text: str) -> tuple[str, str]:
    """A requirements_txt entry's text before its comment, and the comment."""
    match = _COMMENT_RE.search(text)
    cut = match.start() if match else len(text)
    return text[:cut], text[cut:]


def requirements_hashes(text: str) -> str:
    """The `--hash` values of a requirements_txt entry, or "" when it has none."""
    return _locked_hashes(_HASH_RE.findall(_code(text)[0]))


def requirements_line(text: str) -> str:
    """A requirements_txt entry's text without its `--hash` options."""
    code, comment = _code(text)
    return _HASH_RE.sub("", code) + comment


def _record(where: str, record: dict) -> str:
    return json.dumps([where, record], sort_keys=True, separators=(",", ":"), default=str)


def _residue(doc: dict) -> str:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str)


def _locked_hashes(hashes: object) -> str:
    """Each hash of a record, sorted and space-separated, or "" when it locks none or one is not a string."""
    if not isinstance(hashes, list) or not hashes or not all(isinstance(item, str) for item in hashes):
        return ""
    return " ".join(sorted(set(hashes)))


def poetry_lock(text: str) -> Parsed | None:
    if not text.strip():
        return [], ""
    try:
        doc = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError):
        return None
    packages = doc.pop("package", [])
    if not isinstance(packages, list) or not all(isinstance(item, dict) for item in packages):
        return None
    if not all(isinstance(item.get("name"), str) and item["name"] for item in packages):
        return None
    metadata = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    metadata.pop("content-hash", None)
    legacy = metadata.get("files") if isinstance(metadata.get("files"), dict) else {}
    # A table joins the first package of its name; a table no package claims stays residue.
    claims = {_requirement_name(key): key for key in legacy}
    if len(claims) < len(legacy):  # two tables share a name, so neither is the package's
        claims = {}
    entries: list[Entry] = []
    for package in packages:
        name = _requirement_name(package["name"])
        # Each table joins at most one package; a repeated name finds its claim gone.
        key = claims.pop(name, None) if "files" not in package else None
        item = {**package, "files": legacy.pop(key)} if key is not None else package
        version = str(item.get("version") or "")
        source = item.get("source")
        if source is not None:
            version = f"{version} ({_residue(source)})"
        entries.append((name, version, True, _record("package", item)))
    return entries, _residue(doc)


def poetry_lock_hashes(text: str) -> str:
    """The `hash` of each of a poetry_lock record's `files`, or "" when one has none."""
    files = json.loads(text)[1].get("files")
    if not isinstance(files, list) or not all(isinstance(item, dict) for item in files):
        return ""
    return _locked_hashes([item.get("hash") for item in files])


# Pipfile.lock keys that install a package from somewhere other than an index.
_PIPFILE_SOURCES = ("git", "path", "file", "editable", "ref")


def pipfile_lock(text: str) -> Parsed | None:
    if not text.strip():
        return [], ""
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError):
        return None
    if not isinstance(doc, dict):
        return None
    entries: list[Entry] = []
    for section in ("default", "develop"):
        block = doc.pop(section, {})
        if not isinstance(block, dict) or not all(isinstance(item, dict) for item in block.values()):
            return None
        for name, record in block.items():
            version = str(record.get("version") or "")
            source = {key: record[key] for key in _PIPFILE_SOURCES if key in record}
            if record.get("index", "pypi") != "pypi":
                source["index"] = record["index"]
            if source:
                version = f"{version} ({_residue(source)})"
            entries.append((_requirement_name(name), version, True, _record(section, {name: record})))
    if isinstance(doc.get("_meta"), dict):
        doc["_meta"].pop("hash", None)
    return entries, _residue(doc)


def pipfile_lock_hashes(text: str) -> str:
    """The `hashes` of a pipfile_lock record, or "" when it has none."""
    record = next(iter(json.loads(text)[1].values()))
    return _locked_hashes(record.get("hashes"))
