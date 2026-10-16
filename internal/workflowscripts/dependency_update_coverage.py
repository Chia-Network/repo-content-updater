"""Scan every Dependabot update. Covered means that update's scan_conclusive is true.

Anything else — missing repo, missing versions, clone failure, or a scan that is
not conclusive — makes the group inconclusive. One report is passed through.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

_REPO_RE = re.compile(r"\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_FINDING_KEYS = ("unicode", "confusable", "ioc", "heuristic")


def scannable(update: dict) -> bool:
    repo = str(update.get("upstreamRepo") or "")
    from_version = str(update.get("fromVersion") or "")
    to_version = str(update.get("toVersion") or "")
    if not _REPO_RE.fullmatch(repo):
        return False
    if not from_version or not to_version:
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


def _covered(report: dict) -> bool:
    return report.get("scan_conclusive") is True


def aggregate(records: list[dict]) -> dict:
    """Covered only when every record was scanned conclusively."""
    if len(records) == 1:
        return records[0]
    if not records:
        return uncovered({}, "incomplete_coverage")

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

    chosen = next((record for record in records if _covered(record) and record.get("resolved_to")), records[0])
    return {
        "status": status,
        "warn_only": warn_only,
        "scan_conclusive": conclusive,
        "not_scanned_reason": "" if conclusive else "incomplete_coverage",
        "verdict_token_in_tree": any(record.get("verdict_token_in_tree") is True for record in records),
        "resolution_strategy": "group",
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
    }


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
        ["git", "clone", "--filter=blob:none", "--", url, str(dest)],
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
    env["FROM_VERSION"] = str(update["fromVersion"])
    env["TO_VERSION"] = str(update["toVersion"])
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


def _emit(report: dict, summary: str) -> None:
    output = os.environ.get("GITHUB_OUTPUT", "").strip()
    if not output:
        return
    delim = f"GHEOF_{uuid.uuid4().hex}"
    conclusive = "true" if report.get("scan_conclusive") is True else "false"
    text = (
        f"status={report.get('status') or ''}\n"
        f"changed_files_count={int(report.get('changed_files_count') or 0)}\n"
        f"resolved_from={report.get('resolved_from') or ''}\n"
        f"resolved_to={report.get('resolved_to') or ''}\n"
        f"from_tag={report.get('from_tag') or ''}\n"
        f"to_tag={report.get('to_tag') or ''}\n"
        f"scan_conclusive={conclusive}\n"
        f"summary<<{delim}\n"
        f"{summary}"
        f"{delim}\n"
    )
    with open(output, "a", encoding="utf-8") as handle:
        handle.write(text)


def _keep_checkout(records: list[dict], scans: list[tuple[dict, Path]]) -> None:
    chosen_to = ""
    for record in records:
        if _covered(record) and record.get("resolved_to"):
            chosen_to = str(record["resolved_to"])
            break
    root = Path.cwd()
    target = root / ".upstream-dependency"
    if target.exists():
        shutil.rmtree(target)
    if not chosen_to:
        return
    for record, dest in scans:
        if str(record.get("resolved_to") or "") != chosen_to:
            continue
        checkout = dest / ".upstream-dependency"
        if checkout.is_dir():
            shutil.move(str(checkout), str(target))
            return


def main() -> None:
    scan_script = Path(__file__).resolve().parent / "upstream_malware_scan.sh"
    updates = _load_updates(Path("dependency_updates.json"))
    work = Path(".dcr-dependency-scans")
    if work.exists():
        shutil.rmtree(work)
    work.mkdir()
    records: list[dict] = []
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
            if len(updates) == 1 and summary_path.is_file():
                child_summary = summary_path.read_text(encoding="utf-8")
        report = aggregate(records)
        summary = child_summary if len(records) == 1 and child_summary else render_summary(report, records)
        Path("malware_scan_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        Path("malware_scan_summary.md").write_text(summary, encoding="utf-8")
        _keep_checkout(records, scans)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    _emit(report, summary)
    if report.get("status") == "fail":
        print("Malware scan failed.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
