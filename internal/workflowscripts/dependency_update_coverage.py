"""Scan every Dependabot update.

A dependency is covered only when its scan is conclusive and both from_tag and
to_tag are set. Anything else makes the group inconclusive.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import uuid
from pathlib import Path

_REPO_RE = re.compile(r"\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_FINDING_KEYS = ("unicode", "confusable", "ioc", "heuristic")


def scannable(update: dict) -> bool:
    """A destination version is enough to read that tree. An empty from stays inconclusive."""
    repo = str(update.get("upstreamRepo") or "")
    from_version = str(update.get("fromVersion") or "")
    to_version = str(update.get("toVersion") or "")
    if not _REPO_RE.fullmatch(repo):
        return False
    if not to_version:
        return False
    if any(char in from_version + to_version for char in "\n\r\x00"):
        return False
    return True


def _label(update: dict) -> str:
    return str(update.get("packageName") or update.get("upstreamRepo") or "dependency")


def uncovered(update: dict, reason: str) -> dict:
    name = _label(update)
    return {
        "status": "not_scanned",
        "warn_only": True,
        "scan_conclusive": False,
        "not_scanned_reason": reason,
        "verdict_token_in_tree": False,
        "resolution_strategy": "unresolved",
        "resolved_range": "",
        "resolved_from": "",
        "resolved_to": "",
        "from_tag": "",
        "to_tag": "",
        "changed_files_count": 0,
        "materialized_count": 0,
        "filtered_count": 0,
        "changed_files": [],
        "errors": [f"{name}: {reason}"],
        "findings": {key: [] for key in _FINDING_KEYS},
        "package_name": str(update.get("packageName") or ""),
        "upstream_repo": str(update.get("upstreamRepo") or ""),
        "from_version": str(update.get("fromVersion") or ""),
        "to_version": str(update.get("toVersion") or ""),
    }


def _tag(update: dict, report: dict) -> dict:
    tagged = dict(report)
    tagged["package_name"] = str(update.get("packageName") or tagged.get("package_name") or "")
    tagged["upstream_repo"] = str(update.get("upstreamRepo") or tagged.get("upstream_repo") or "")
    tagged["from_version"] = str(update.get("fromVersion") or "")
    tagged["to_version"] = str(update.get("toVersion") or "")
    if tagged.get("scan_conclusive") is not True:
        tagged["scan_conclusive"] = False
    return tagged


def _tagged(report: dict) -> bool:
    return bool(str(report.get("from_tag") or "").strip()) and bool(str(report.get("to_tag") or "").strip())


def _covered(report: dict) -> bool:
    """Conclusive tag-to-tag scan. A branch, raw SHA, or HEAD does not count."""
    return report.get("scan_conclusive") is True and _tagged(report)


def _apply_coverage(report: dict) -> dict:
    covered = _covered(report)
    stamped = dict(report)
    stamped["scan_conclusive"] = covered
    if not covered:
        if not str(stamped.get("not_scanned_reason") or "").strip():
            stamped["not_scanned_reason"] = "incomplete_coverage"
        if stamped.get("status") not in {"fail", "warn"}:
            stamped["status"] = "not_scanned"
    return stamped


def agent_target(records: list[dict]) -> tuple[str, str, str] | None:
    """Pure (package, repository, resolved commit) selection. Does not clone."""
    for record in records:
        repo = str(record.get("upstream_repo") or "")
        resolved_to = str(record.get("resolved_to") or "")
        if _covered(record) and repo and resolved_to:
            return (str(record.get("package_name") or ""), repo, resolved_to)
    return None


def _identity(record: dict) -> tuple[str, str, str]:
    return (
        str(record.get("package_name") or ""),
        str(record.get("upstream_repo") or ""),
        str(record.get("resolved_to") or ""),
    )


def _candidate(record: dict) -> dict:
    return {
        "package_name": str(record.get("package_name") or ""),
        "upstream_repo": str(record.get("upstream_repo") or ""),
        "resolved_to": str(record.get("resolved_to") or ""),
        "resolved_from": str(record.get("resolved_from") or ""),
        "from_version": str(record.get("from_version") or ""),
        "to_version": str(record.get("to_version") or ""),
        "from_tag": str(record.get("from_tag") or ""),
        "to_tag": str(record.get("to_tag") or ""),
        "scan_conclusive": _covered(record),
    }


def _stamp(report: dict, records: list[dict], target: tuple[str, str, str] | None) -> dict:
    report["agent_candidates"] = [_candidate(record) for record in records]
    report["agent_target"] = list(target) if target else None
    return report


def _selected(records: list[dict], target: tuple[str, str, str] | None) -> dict:
    if target is None:
        return {}
    return next((record for record in records if _identity(record) == target), {})


def agent_fields(records: list[dict]) -> dict[str, str]:
    """Prompt fields for agent_target. Empty when no dependency was scanned conclusively."""
    target = agent_target(records)
    if target is None:
        return {
            "package": "",
            "from_version": "",
            "to_version": "",
            "resolved_from": "",
            "resolved_to": "",
        }
    chosen = _selected(records, target)
    return {
        "package": target[0],
        "from_version": str(chosen.get("from_version") or ""),
        "to_version": str(chosen.get("to_version") or ""),
        "resolved_from": str(chosen.get("resolved_from") or ""),
        "resolved_to": target[2],
    }


def _unread_items(records: list[dict]) -> list[dict]:
    found: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for record in records:
        for item in record.get("unread") or []:
            if not isinstance(item, dict):
                continue
            file_name = item.get("file")
            cause = item.get("cause")
            if not isinstance(file_name, str) or not file_name.strip():
                continue
            why = cause.strip() if isinstance(cause, str) and cause.strip() else "incomplete"
            key = (file_name.strip(), why)
            if key in seen:
                continue
            seen.add(key)
            found.append({"file": file_name.strip(), "cause": why})
    return found


def aggregate(records: list[dict]) -> dict:
    """Covered only when every record was scanned conclusively."""
    target = agent_target(records)
    if len(records) == 1:
        return _stamp(_apply_coverage(records[0]), records, target)
    if not records:
        return _stamp(uncovered({}, "incomplete_coverage"), records, None)

    findings = {key: [] for key in _FINDING_KEYS}
    errors: list[str] = []
    changed: list[str] = []
    for record in records:
        name = str(record.get("package_name") or record.get("upstream_repo") or "dependency")
        if not _covered(record):
            reason = str(record.get("not_scanned_reason") or "not_conclusive")
            errors.append(f"{name}: {reason}")
        for key in _FINDING_KEYS:
            items = (record.get("findings") or {}).get(key) or []
            if isinstance(items, list):
                findings[key].extend(items)
        for item in record.get("errors") or []:
            if item not in errors:
                errors.append(str(item))
        for path in record.get("changed_files") or []:
            changed.append(f"{name}:{path}")

    conclusive = all(_covered(record) for record in records)
    any_findings = any(findings.values())
    warn_only = all(record.get("warn_only") is not False for record in records)
    if any(record.get("status") == "fail" for record in records):
        status = "fail"
    elif any_findings:
        status = "warn" if warn_only else "fail"
    elif not conclusive:
        status = "not_scanned"
    else:
        status = "clean"

    chosen = _selected(records, target)
    return _stamp(
        {
            "status": status,
            "warn_only": warn_only,
            "scan_conclusive": conclusive,
            "not_scanned_reason": "" if conclusive else "incomplete_coverage",
            "verdict_token_in_tree": any(record.get("verdict_token_in_tree") is True for record in records),
            "resolution_strategy": "group",
            "package_name": chosen.get("package_name") or "",
            "upstream_repo": chosen.get("upstream_repo") or "",
            "from_version": chosen.get("from_version") or "",
            "to_version": chosen.get("to_version") or "",
            "resolved_range": chosen.get("resolved_range") or "",
            "resolved_from": chosen.get("resolved_from") or "",
            "resolved_to": chosen.get("resolved_to") or "",
            "from_tag": chosen.get("from_tag") or "",
            "to_tag": chosen.get("to_tag") or "",
            "changed_files_count": sum(int(record.get("changed_files_count") or 0) for record in records),
            "materialized_count": sum(int(record.get("materialized_count") or 0) for record in records),
            "filtered_count": sum(int(record.get("filtered_count") or 0) for record in records),
            "changed_files": changed,
            "errors": errors,
            "findings": findings,
            "unread": _unread_items(records),
            "dependencies": [
                {
                    "package_name": record.get("package_name") or "",
                    "upstream_repo": record.get("upstream_repo") or "",
                    "from_version": record.get("from_version") or "",
                    "to_version": record.get("to_version") or "",
                    "scan_conclusive": _covered(record),
                    "not_scanned_reason": record.get("not_scanned_reason") or "",
                }
                for record in records
            ],
        },
        records,
        target,
    )


def render_summary(report: dict, records: list[dict]) -> str:
    lines = ["## Malware Scan Summary", "", f"- Status: **{report.get('status') or 'not_scanned'}**"]
    if report.get("scan_conclusive") is True:
        lines.append("- Scan coverage: **conclusive**.")
    else:
        reason = report.get("not_scanned_reason") or "incomplete_coverage"
        lines.append(f"- Scan coverage: **incomplete** (`{reason}`).")
        lines.append("- A dependency is covered only when its scan is conclusive.")
        lines.append("- This is not a benign result.")
    for record in records:
        name = record.get("package_name") or record.get("upstream_repo") or "dependency"
        span = f"{record.get('from_version') or '?'} -> {record.get('to_version') or '?'}"
        repo = record.get("upstream_repo") or "no repository"
        if _covered(record):
            lines.append(f"- {name} {span} ({repo}): covered")
        else:
            reason = record.get("not_scanned_reason") or "not_conclusive"
            lines.append(f"- {name} {span} ({repo}): not covered ({reason})")
    if not any_read(report):
        lines.append("- This status is inconclusive. It is not evidence the package is benign.")
    return "\n".join(lines) + "\n"


def any_read(report: dict) -> bool:
    return int(report.get("materialized_count") or 0) > 0


_BASE_REF_RE = re.compile(r"\A[A-Za-z0-9._/-]+\Z")
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


def _json_dep_map(doc: object) -> dict[str, str]:
    found: dict[str, str] = {}
    if not isinstance(doc, dict):
        return found
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        block = doc.get(section)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            if isinstance(spec, str):
                found[str(name)] = spec
            elif isinstance(spec, dict) and spec.get("version"):
                found[str(name)] = str(spec["version"])
    packages = doc.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if not isinstance(key, str) or not isinstance(meta, dict):
                continue
            name = _direct_lock_name(key)
            if not name:
                continue
            version = meta.get("version")
            if version:
                found[name] = str(version)
    return found


def _direct_lock_name(key: str) -> str:
    prefix = "node_modules/"
    if not key.startswith(prefix) or "/node_modules/" in key[len(prefix) :]:
        return ""
    return key[len(prefix) :]


def _load_json_map(text: str) -> dict[str, str] | None:
    try:
        return _json_dep_map(json.loads(text))
    except json.JSONDecodeError:
        return None


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


def _go_mod_map(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for kind, line in _go_mod_lines(text):
        if kind != "entry":
            continue
        match = _GO_MOD_RE.match(line.split("//", 1)[0])
        if match:
            found[match.group(1)] = match.group(2)
    return found


def _go_sum_map(text: str) -> dict[str, str]:
    found: dict[str, set[str]] = {}
    for match in _GO_SUM_RE.finditer(text):
        found.setdefault(match.group(1), set()).add(match.group(2))
    return {name: " ".join(sorted(versions)) for name, versions in found.items()}


def _requirements_map(text: str) -> dict[str, str]:
    return {match.group(1).lower(): match.group(2) for match in _REQ_RE.finditer(text)}


def _yarn_map(text: str) -> dict[str, str]:
    found: dict[str, set[str]] = {}
    names: list[str] = []
    for line in text.splitlines():
        if line and not line.startswith((" ", "\t")):
            names = _YARN_HEADER_RE.findall(line)
            continue
        match = _YARN_VERSION_RE.match(line)
        if match:
            for name in names:
                found.setdefault(name, set()).add(match.group(1))
    return {name: " ".join(sorted(versions)) for name, versions in found.items()}


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


def _versions_for(kind: str, text: str) -> dict[str, str] | None:
    if kind == "opaque":
        return None
    if kind == "json":
        if not text.strip():
            return {}
        return _load_json_map(text)
    if kind == "go.mod":
        return _go_mod_map(text)
    if kind == "go.sum":
        return _go_sum_map(text)
    if kind == "yarn":
        return _yarn_map(text)
    if kind == "requirements":
        return _requirements_map(text)
    return {}


def _changed_names(kind: str, before: str, after: str) -> set[str] | None:
    old = _versions_for(kind, before)
    new = _versions_for(kind, after)
    if old is None or new is None:
        return None
    names = set(old) | set(new)
    return {name for name in names if old.get(name) != new.get(name)}


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


def _go_mod_parts(text: str) -> tuple[dict[str, tuple[str, str]], str]:
    entries: dict[str, tuple[str, str]] = {}
    residue: list[str] = []
    for kind, line in _go_mod_lines(text):
        code = line.split("//", 1)[0]
        match = _GO_MOD_RE.match(code) if kind == "entry" else None
        if match:
            entries[match.group(1)] = (match.group(2), code.strip())
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


def _req_parts(text: str) -> tuple[dict[str, tuple[str, str]], str]:
    entries: dict[str, tuple[str, str]] = {}
    residue: list[str] = []
    for line in text.splitlines(keepends=True):
        match = _REQ_RE.match(line)
        if match:
            entries[match.group(1).lower()] = (match.group(2), line.strip())
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


def _blocks_explain(
    name: str,
    old_blocks: list[tuple[str, str]],
    new_blocks: list[tuple[str, str]],
    listed: dict[str, set[tuple[str, str]]],
) -> bool:
    old_left = list(old_blocks)
    new_left = list(new_blocks)
    for block in list(old_left):
        if block in new_left:
            old_left.remove(block)
            new_left.remove(block)
    if not old_left and not new_left:
        return True
    if len(old_left) != len(new_left):
        return False
    old_versions = {version for version, _payload in old_left}
    new_versions = {version for version, _payload in new_left}
    if len(old_versions) != 1 or len(new_versions) != 1:
        return False
    return _reached_listed_version(name, min(old_versions), min(new_versions), listed)


def _entries_explain(kind: str, before: str, after: str, updates: list[dict]) -> bool:
    """True when every changed entry moved to its listed version.

    Checksums on that entry are part of the change. A same-version entry,
    an unlisted package, a replace line, an extra descriptor, or any other
    residue is not.
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
        _blocks_explain(name, _entry_blocks(old_entries.get(name)), _entry_blocks(new_entries.get(name)), listed)
        for name in names
    )


def _git_text(rev: str, path: str) -> str:
    proc = subprocess.run(
        ["git", "show", f"{rev}:{path}"],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return ""
    return proc.stdout


def _verify_commit(rev: str) -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "--verify", "--end-of-options", f"{rev}^{{commit}}"],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip()


def _fetch_commit(sha: str) -> str:
    found = _verify_commit(sha)
    if found:
        return found
    subprocess.run(
        ["git", "fetch", "--no-tags", "--depth=1", "origin", sha],
        check=False,
        capture_output=True,
        text=True,
    )
    return _verify_commit(sha)


def _base_commit() -> str | None:
    """Resolved base commit, '' when a named base cannot be read, None when unnamed."""
    if not Path(".git").is_dir():
        return None
    sha = os.environ.get("PR_BASE_SHA", "").strip()
    if sha:
        if not re.fullmatch(r"[0-9a-fA-F]{7,64}", sha):
            return ""
        return _fetch_commit(sha)
    ref = os.environ.get("GITHUB_BASE_REF", "").strip()
    if not ref:
        return None
    if not _BASE_REF_RE.fullmatch(ref):
        return ""
    return _verify_commit(ref) or _verify_commit(f"origin/{ref}") or ""


def manifest_gaps(updates: list[dict]) -> list[dict]:
    """Direct manifest and lockfile bumps missing from the parsed list.

    An unreadable base ref, when one was named, is itself unresolved.
    An entry is explained only when its package moved to the listed version.
    Anything else in the file stays unresolved under the path.
    """
    base = _base_commit()
    if base is None:
        return []
    if not base:
        return [uncovered({"packageName": "manifest-diff"}, "unresolved")]
    listed = {str(item.get("packageName") or "").strip() for item in updates}
    diff = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=AM", base, "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    if diff.returncode != 0:
        return [uncovered({"packageName": "manifest-diff"}, "unresolved")]
    gaps: list[dict] = []
    seen = set(listed)
    for path in diff.stdout.splitlines():
        kind = _manifest_kind(path)
        if not kind:
            continue
        before = _git_text(base, path)
        after = _git_text("HEAD", path)
        names = _changed_names(kind, before, after)
        explained = names is not None and _entries_explain(kind, before, after, updates)
        if names is None or (before != after and names <= listed and not explained):
            labels = [path]
        else:
            labels = sorted(names)
        for label in labels:
            if label in seen:
                continue
            gaps.append(uncovered({"packageName": label}, "unresolved"))
            seen.add(label)
    return gaps


def _load_updates(path: Path) -> list[dict]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)]


def _clone(repo: str, dest: Path) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    url = f"https://github.com/{repo}.git"
    proc = subprocess.run(
        ["git", "clone", "--", url, str(dest)],
        check=False,
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0 and dest.is_dir()


def _scan_one(update: dict, dest: Path, scan_script: Path) -> dict:
    if not scannable(update):
        return uncovered(update, "unresolved")
    checkout = dest / ".upstream-dependency"
    if not _clone(str(update["upstreamRepo"]), checkout):
        return uncovered(update, "unresolved")
    env = os.environ.copy()
    env["GITHUB_OUTPUT"] = str(dest / "github_output.txt")
    env["PACKAGE_NAME"] = str(update.get("packageName") or "")
    env["FROM_VERSION"] = str(update.get("fromVersion") or "")
    env["TO_VERSION"] = str(update.get("toVersion") or "")
    proc = subprocess.run(
        ["bash", str(scan_script)],
        cwd=dest,
        env=env,
        check=False,
    )
    report_path = dest / "malware_scan_report.json"
    if not report_path.is_file():
        return uncovered(update, "not_scanned")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return uncovered(update, "not_scanned")
    if not isinstance(report, dict):
        return uncovered(update, "not_scanned")
    tagged = _tag(update, report)
    if proc.returncode != 0 and tagged.get("status") != "fail":
        tagged["scan_conclusive"] = False
        tagged["not_scanned_reason"] = tagged.get("not_scanned_reason") or "not_scanned"
    return tagged


def _output_field(value: object) -> str:
    return str(value or "").replace("\r", " ").replace("\n", " ")


def _emitted_fields(report: dict) -> dict:
    """Outputs follow agent_target. A scan record's own commit is not a second choice."""
    target = report.get("agent_target")
    if not isinstance(target, list) or len(target) != 3:
        return {}
    want = (str(target[0]), str(target[1]), str(target[2]))
    for item in report.get("agent_candidates") or []:
        if isinstance(item, dict) and _identity(item) == want:
            return item
    return {"package_name": want[0], "upstream_repo": want[1], "resolved_to": want[2]}


def _emit(report: dict, summary: str) -> None:
    output = os.environ.get("GITHUB_OUTPUT", "").strip()
    if not output:
        return
    fields = _emitted_fields(report)
    delim = f"GHEOF_{uuid.uuid4().hex}"
    conclusive = "true" if report.get("scan_conclusive") is True else "false"
    text = (
        f"status={_output_field(report.get('status'))}\n"
        f"changed_files_count={int(report.get('changed_files_count') or 0)}\n"
        f"package_name={_output_field(fields.get('package_name'))}\n"
        f"upstream_repo={_output_field(fields.get('upstream_repo'))}\n"
        f"from_version={_output_field(fields.get('from_version'))}\n"
        f"to_version={_output_field(fields.get('to_version'))}\n"
        f"resolved_from={_output_field(fields.get('resolved_from'))}\n"
        f"resolved_to={_output_field(fields.get('resolved_to'))}\n"
        f"from_tag={_output_field(fields.get('from_tag'))}\n"
        f"to_tag={_output_field(fields.get('to_tag'))}\n"
        f"scan_conclusive={conclusive}\n"
        f"summary<<{delim}\n"
        f"{summary}"
        f"{delim}\n"
    )
    with open(output, "a", encoding="utf-8") as handle:
        handle.write(text)


def _keep_checkout(records: list[dict], scans: list[tuple[dict, Path]]) -> None:
    target = agent_target(records)
    kept = Path.cwd() / ".upstream-dependency"
    if kept.exists():
        shutil.rmtree(kept)
    if target is None:
        return
    for record, dest in scans:
        if _identity(record) != target:
            continue
        checkout = dest / ".upstream-dependency"
        if checkout.is_dir():
            shutil.move(str(checkout), str(kept))
        return


def main() -> None:
    scan_script = Path(__file__).resolve().parent / "upstream_malware_scan.sh"
    updates = _load_updates(Path("dependency_updates.json"))
    gaps = manifest_gaps(updates)
    work = Path(".dcr-dependency-scans")
    if work.exists():
        shutil.rmtree(work)
    work.mkdir()
    records: list[dict] = list(gaps)
    scans: list[tuple[dict, Path]] = []
    child_summary = ""
    try:
        for index, update in enumerate(updates):
            dest = work / str(index)
            dest.mkdir()
            record = _scan_one(update, dest, scan_script)
            records.append(record)
            scans.append((record, dest))
            summary_path = dest / "malware_scan_summary.md"
            if len(updates) == 1 and not gaps and summary_path.is_file():
                child_summary = summary_path.read_text(encoding="utf-8")
        report = aggregate(records)
        summary = child_summary if len(records) == 1 and child_summary else render_summary(report, records)
        Path("malware_scan_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        Path("malware_scan_summary.md").write_text(summary, encoding="utf-8")
        _keep_checkout(records, scans)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    _emit(report, summary)


if __name__ == "__main__":
    main()
