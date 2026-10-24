"""requirements, pyproject, setup.py, setup.cfg and Pipfile grammar.

requirements returns (entries, residue). An entry is (PEP 503 name, version
token, top, text); every declared requirement is top. The token keeps its
operator, so `==1.2.3` is exact and `>=1.2` is a range. text is the line with
each of its version tokens masked, so the rest of the line cannot change unseen.
"""

from __future__ import annotations

import re

_REQ_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*((?:===|==|~=|!=|>=|<=|>|<)\s*[^\s#;,]+)")
# A TOML table header, and a `name = "spec"` or `name = { version = "spec" }` dependency line.
_TOML_TABLE_RE = re.compile(r"^\s*\[+\s*([^\]]+?)\s*\]+\s*$")
_TOML_DEP_RE = re.compile(
    r'^\s*"?([A-Za-z0-9][A-Za-z0-9._-]*)"?\s*=\s*(?:\{[^}]*?\bversion\s*=\s*)?["\']([^"\']+)["\']'
)
_QUOTED_RE = re.compile(r'["\']([^"\']+)["\']')
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


def requirements(text: str) -> tuple[list[tuple[str, str, bool, str]], str]:
    entries: list[tuple[str, str, bool, str]] = []
    residue: list[str] = []
    table = ""
    for line in text.splitlines(keepends=True):
        header = _TOML_TABLE_RE.match(line)
        table = header.group(1) if header else table
        found = _requirement_specs(line, table)
        masked = line.strip()
        for _name, version in found:
            masked = masked.replace(version, "\0", 1)
        entries.extend((_requirement_name(name), version, True, masked) for name, version in found)
        if not found:
            residue.append(line)
    return entries, "".join(residue)
