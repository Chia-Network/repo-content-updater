"""Fetch published artifacts for a Dependabot PR and write a review bundle.

The update list (`dependabot/fetch-metadata`), PR diff (`gh pr diff`) and PR
files API list are untrusted. Names and versions are validated per ecosystem,
passed as argv, and extracted archives are checked for links and traversal.
Writes the artifact trees, `changes.diff`, `files.txt` and `meta.json` under
`DCR_OUT`.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from dcr_lock import (
    URL_PATTERN,
    Hunk,
    added_lines,
    binding_on_added,
    hunk_matches,
    hunk_near,
    locked_hashes,
    parse_hunks,
    read_changed_files,
)
from dcr_sources import (
    PYPI_ALLOWED_HOSTS,
    Candidate,
    FetchError,
    extract,
    fetch_action,
    fetch_gomod,
    fetch_npm,
    fetch_pypi,
    format_from_name,
)

MAX_UPDATES = 10
MAX_DIFF_BYTES = 2 * 1024 * 1024
BIDI_CONTROL = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
UPDATE_FIELDS = ("dependencyName", "packageEcosystem", "prevVersion", "newVersion")
VERSION_WINDOW = 3
INDEX_WINDOW = 8

NPM_NAME = re.compile(r"^(?=.{1,214}$)(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")
NPM_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
PIP_NAME = re.compile(r"^(?=.{1,214}$)[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
PIP_VERSION = re.compile(
    r"^(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?"
    r"(?:\+[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*)?$",
    re.IGNORECASE,
)
GO_NAME = re.compile(r"^(?=.{1,300}$)(?!.*(?:^|/)\.\.?(?:/|$))[A-Za-z0-9][A-Za-z0-9._~/-]*$")
GO_VERSION = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+incompatible)?$")
ACTION_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
ACTION_SHA = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class Update:
    name: str
    ecosystem: str
    directory: str
    prev_version: str
    new_version: str
    status: str = "reviewed"
    bound: bool = False
    note: str = ""


@dataclass(frozen=True)
class Review:
    """The files chosen for review and the binding decision they produce."""

    candidates: tuple[Candidate, ...] = ()
    bound: bool = False
    status: str = "reviewed"
    note: str = ""


FetchFn = Callable[[Path, str, str], tuple[Candidate, ...]]


@dataclass(frozen=True)
class Ecosystem:
    """One reviewed ecosystem: grammars and fetcher."""

    name: re.Pattern[str]
    version: re.Pattern[str]
    fetch: FetchFn


def _pypi_index_note(update: Update, hunks: Sequence[Hunk]) -> str | None:
    """Reject a package entry whose URLs are not on the public PyPI hosts."""
    for hunk in hunks:
        for side in ("new", "old"):
            for _kind, line in hunk_near(hunk, update.name, INDEX_WINDOW, update.ecosystem, side):
                for match in URL_PATTERN.finditer(line):
                    parsed = urllib.parse.urlsplit(match.group(0))
                    if parsed.scheme != "https" or parsed.hostname not in PYPI_ALLOWED_HOSTS:
                        return "non-default package index"
    return None


def _safe_label(filename: str) -> str:
    """A single safe path component for one distribution's extraction directory."""
    return re.sub(r"[^A-Za-z0-9._@-]", "_", filename).strip(".") or "artifact"


def _pypi_label(filename: str, version: str) -> str:
    """A version-free label so old and new distributions share a directory."""
    return _safe_label(filename.replace(version, "VERSION"))


def _pypi_files(
    update: Update,
    candidates: tuple[Candidate, ...],
    hunks: Sequence[Hunk],
    is_new: bool,
    new_review: Review | None = None,
) -> Review:
    """Review the new distributions the lock binds, and the matching old ones."""
    if not is_new:
        reviewed = new_review.candidates if new_review else ()
        old_names = {
            candidate.filename.replace(update.new_version, update.prev_version): candidate for candidate in reviewed
        }
        selected = tuple(
            replace(candidate, label=_pypi_label(old_names[candidate.filename].filename, update.new_version))
            for candidate in candidates
            if candidate.filename in old_names
        )
        return Review(selected)
    locked = locked_hashes(update.name, hunks)
    if not locked:
        selected = candidates
        return Review(
            tuple(
                replace(candidate, label=_pypi_label(candidate.filename, update.new_version)) for candidate in selected
            ),
            note="not bound to the lockfile",
        )
    selected = tuple(candidate for candidate in candidates if candidate.binding in locked)
    labeled = tuple(
        replace(candidate, label=_pypi_label(candidate.filename, update.new_version)) for candidate in selected
    )
    if locked <= {candidate.binding for candidate in candidates}:
        return Review(labeled, bound=True)
    return Review(labeled, status="unverified", note="partially bound")


ECOSYSTEMS: dict[str, Ecosystem] = {
    "npm_and_yarn": Ecosystem(NPM_NAME, NPM_VERSION, fetch_npm),
    "pip": Ecosystem(PIP_NAME, PIP_VERSION, fetch_pypi),
    "gomod": Ecosystem(GO_NAME, GO_VERSION, fetch_gomod),
    "github_actions": Ecosystem(ACTION_NAME, ACTION_SHA, fetch_action),
}

ALLOWED_CHANGED_FILES: dict[str, tuple[re.Pattern[str], ...]] = {
    "npm_and_yarn": (
        re.compile(r"(?:^|/)(?:package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml)$"),
    ),
    "pip": (
        re.compile(r"(?:^|/)requirements[^/]*\.(?:txt|in)$"),
        re.compile(r"(?:^|/)requirements/[^/]+\.txt$"),
        re.compile(r"(?:^|/)(?:pyproject\.toml|poetry\.lock|uv\.lock|Pipfile|Pipfile\.lock|setup\.cfg|setup\.py)$"),
    ),
    "gomod": (re.compile(r"(?:^|/)go\.(?:mod|sum)$"),),
    "github_actions": (
        re.compile(r"(?:^|/)\.github/workflows/.+\.ya?ml$"),
        re.compile(r"(?:^|/)action\.ya?ml$"),
    ),
    "cargo": (re.compile(r"(?:^|/)(?:Cargo\.toml|Cargo\.lock)$"),),
}


ECOSYSTEM_ALIASES = {"go_modules": "gomod"}


def _normalize_versions(update: Update) -> Update:
    """Dependabot reports Go versions without the leading `v` that go.mod and go.sum use."""
    if update.ecosystem != "gomod":
        return update
    prev_version, new_version = (
        version if version.startswith("v") else f"v{version}" for version in (update.prev_version, update.new_version)
    )
    return replace(update, prev_version=prev_version, new_version=new_version)


def _parse_updates(raw: str) -> list[Update]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit("updated-dependencies-json is not valid JSON") from exc
    if not isinstance(payload, list):
        raise SystemExit("updated-dependencies-json must be a list")
    updates: list[Update] = []
    for item in payload:
        values = [item.get(key) if isinstance(item, dict) else None for key in UPDATE_FIELDS]
        if not all(isinstance(value, str) and value for value in values):
            raise SystemExit("updated dependency is missing a required field")
        directory = item.get("directory", "")
        name, ecosystem, prev_version, new_version = values
        update = Update(
            name,
            ECOSYSTEM_ALIASES.get(ecosystem, ecosystem),
            directory if isinstance(directory, str) else "",
            prev_version,
            new_version,
        )
        updates.append(_normalize_versions(update))
    return updates


def _head_ecosystem(head_ref: str) -> str | None:
    """The update ecosystem named by a `dependabot/<ecosystem>/...` head branch."""
    parts = head_ref.split("/")
    if len(parts) < 3 or parts[0] != "dependabot" or not parts[1]:
        return None
    return ECOSYSTEM_ALIASES.get(parts[1], parts[1])


def _status(
    update: Update,
    head_ecosystem: str | None,
    scope_note: str | None,
    over_cap: bool,
) -> Update | None:
    """The final Update when it must not be fetched, or None when it should be."""
    if head_ecosystem is None:
        return replace(update, status="unverified", note="head branch does not name the update ecosystem")
    if head_ecosystem != update.ecosystem:
        return replace(update, status="unverified", note="head branch names a different update ecosystem")
    ecosystem = ECOSYSTEMS.get(update.ecosystem)
    reviewable = ecosystem is not None and (
        update.ecosystem != "github_actions" or bool(ACTION_SHA.fullmatch(update.new_version))
    )
    if over_cap:
        if not reviewable:
            return replace(update, status="not_reviewed", note=f"over the {MAX_UPDATES}-update cap")
        return replace(update, status="unverified", note=scope_note or f"over the {MAX_UPDATES}-update cap")
    if ecosystem is None:
        return replace(update, status="not_reviewed", note="ecosystem is not reviewed")
    if update.ecosystem == "github_actions" and not ACTION_SHA.fullmatch(update.new_version):
        return replace(update, status="not_reviewed", note="moving ref: the new pin is not a 40-hex commit SHA")
    if scope_note:
        return replace(update, status="unverified", note=scope_note)
    return None


def _scope_note(head_ecosystem: str | None, files: tuple[str, ...]) -> str | None:
    """The fail-closed reason when a changed file is outside the head ecosystem's files."""
    allowed = ALLOWED_CHANGED_FILES.get(head_ecosystem or "")
    if allowed is None:
        return None
    for path in files:
        if not any(pattern.search(path) for pattern in allowed):
            return f"changed file outside the update ecosystem: {path}"
    return None


def _changed_files() -> tuple[str, ...] | None:
    """The PR's changed paths, or None when the files API list is unavailable."""
    return read_changed_files(os.environ.get("PR_FILES_PATH"))


def _check(update: Update, ecosystem: Ecosystem, hunks: Sequence[Hunk]) -> str | None:
    """Return an unverified reason, or None when the update passes the literal checks."""
    if not any(
        hunk_matches(hunk, update.name, update.new_version, update.prev_version, VERSION_WINDOW, update.ecosystem)
        for hunk in hunks
    ):
        return "name and version were not found on the expected diff lines"
    if not ecosystem.name.fullmatch(update.name) or not all(
        ecosystem.version.fullmatch(version) for version in (update.new_version, update.prev_version)
    ):
        return "name or version does not match the ecosystem grammar"
    if update.ecosystem == "pip" and (note := _pypi_index_note(update, hunks)):
        return note
    return None


def _process_update(
    index: int,
    update: Update,
    out_dir: Path,
    hunks: Sequence[Hunk],
    scope_note: str | None = None,
) -> Update:
    if status := _status(update, update.ecosystem, scope_note, False):
        return status
    ecosystem = ECOSYSTEMS[update.ecosystem]
    if note := _check(update, ecosystem, hunks):
        return replace(update, status="unverified", note=note)
    slug = f"{index:02d}-" + re.sub(r"[^A-Za-z0-9._@-]", "_", f"{update.name}@{update.new_version}")
    try:
        with tempfile.TemporaryDirectory() as tmp_old, tempfile.TemporaryDirectory() as tmp_new:
            old_candidates = ecosystem.fetch(Path(tmp_old), update.name, update.prev_version)
            new_candidates = ecosystem.fetch(Path(tmp_new), update.name, update.new_version)
            if update.ecosystem == "pip":
                new_review = _pypi_files(update, new_candidates, hunks, True)
                old_review = _pypi_files(update, old_candidates, hunks, False, new_review)
            else:
                added = [body for hunk in hunks for kind, body in hunk.lines if kind == "+"]
                bound = bool(new_candidates) and all(
                    binding_on_added(candidate.binding, added) for candidate in new_candidates
                )
                new_review = Review(new_candidates, bound=bound, note="" if bound else "not bound to the lockfile")
                old_review = Review(old_candidates)
            for side, review in (("old", old_review), ("new", new_review)):
                for candidate in review.candidates:
                    archive = candidate.load()
                    extract(archive, out_dir / side / slug / candidate.label, format_from_name(candidate.filename))
    except (FetchError, OSError) as exc:
        return replace(update, status="fetch_failed", note=str(exc))
    if new_review.status != "reviewed":
        return replace(update, status=new_review.status, note=new_review.note)
    return replace(update, bound=new_review.bound, note=new_review.note)


def write_diff(out_dir: Path) -> bool:
    """Write changes.diff and report whether the 2 MiB cap truncated it."""
    (out_dir / "old").mkdir(exist_ok=True)
    (out_dir / "new").mkdir(exist_ok=True)
    try:
        result = subprocess.run(["diff", "-ruNa", "old", "new"], cwd=out_dir, check=False, capture_output=True)
    except OSError as exc:
        raise FetchError(f"diff could not run: {exc}") from exc
    if result.returncode not in {0, 1}:
        stderr = result.stderr
        detail = stderr if isinstance(stderr, str) else stderr.decode("utf-8", "replace")
        raise FetchError(f"diff exited {result.returncode}: {detail.strip()[:500]}")
    data = result.stdout
    truncated = len(data) > MAX_DIFF_BYTES
    if truncated:
        data = data[:MAX_DIFF_BYTES] + b"\n[changes.diff truncated at 2 MiB]\n"
    (out_dir / "changes.diff").write_text(data.decode("utf-8", "replace"), encoding="utf-8")
    return truncated


def write_file_list(out_dir: Path) -> list[str]:
    """Write and return every artifact path except the bundle's own outputs."""
    paths = sorted(path.relative_to(out_dir).as_posix() for path in out_dir.rglob("*") if path.is_file())
    paths = [path for path in paths if path not in {"meta.json", "changes.diff", "files.txt"}]
    (out_dir / "files.txt").write_text("\n".join(paths) + ("\n" if paths else ""), encoding="utf-8")
    return paths


def ioc_patterns() -> list[tuple[str, re.Pattern[str]]]:
    """The configured IOC regexes, or a failure when the configuration is not usable."""
    raw = os.environ.get("DEPENDABOT_CURSOR_MALWARE_IOC_PATTERNS", "")
    try:
        patterns = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit("DEPENDABOT_CURSOR_MALWARE_IOC_PATTERNS is not valid JSON") from exc
    if not isinstance(patterns, list) or not patterns or not all(isinstance(p, str) and p for p in patterns):
        raise SystemExit("DEPENDABOT_CURSOR_MALWARE_IOC_PATTERNS must be a non-empty list of non-empty strings")
    try:
        return [(pattern, re.compile(pattern)) for pattern in patterns]
    except re.error as exc:
        raise SystemExit("an IOC pattern is not a valid regex") from exc


def scan_diff(path: Path, patterns: Sequence[tuple[str, re.Pattern[str]]]) -> list[dict[str, object]]:
    """IOC and bidi-control hits on the added lines of a diff file."""
    hits: list[dict[str, object]] = []
    text = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
    for number, body in added_lines(text):
        hits.extend(
            {"kind": "ioc", "pattern": source, "line": number, "match": match.group(0)[:80]}
            for source, pattern in patterns
            if (match := pattern.search(body)) is not None
        )
        if BIDI_CONTROL.search(body) is not None:
            hits.append({"kind": "bidi", "pattern": "bidi-control", "line": number})
    return hits


def main() -> int:
    """Read the update list and PR diff, then write the review bundle."""
    out_dir = Path(os.environ["DCR_OUT"])
    out_dir.mkdir(parents=True, exist_ok=True)
    patterns = ioc_patterns()
    updates = _parse_updates(os.environ.get("UPDATED_DEPENDENCIES_JSON", ""))
    diff_text = Path(os.environ["PR_DIFF_PATH"]).read_text(encoding="utf-8", errors="replace")
    hunks = parse_hunks(diff_text)
    head_ecosystem = _head_ecosystem(os.environ.get("DCR_HEAD_REF", ""))
    files = _changed_files()
    scope_note = "changed file list unavailable" if files is None else _scope_note(head_ecosystem, files)
    results: list[Update] = []
    for index, update in enumerate(updates):
        status = _status(update, head_ecosystem, scope_note, index >= MAX_UPDATES)
        results.append(status if status is not None else _process_update(index, update, out_dir, hunks, scope_note))
    try:
        truncated = write_diff(out_dir)
    except FetchError as exc:
        results = [
            replace(result, status="fetch_failed", note=f"diff failed: {exc}")
            if result.status == "reviewed"
            else result
            for result in results
        ]
        truncated = False
    if truncated:
        results = [
            replace(result, status="truncated", note="changes.diff exceeded the 2 MiB cap")
            if result.status == "reviewed"
            else result
            for result in results
        ]
    file_list = write_file_list(out_dir)
    hits = scan_diff(out_dir / "changes.diff", patterns)
    reviewable = any(result.status != "not_reviewed" for result in results)
    meta = {
        "schema": 1,
        "max_updates": MAX_UPDATES,
        "truncated": truncated,
        "reviewable": reviewable,
        "updates": [asdict(result) for result in results],
        "ioc_hits": hits,
        "files": file_list,
    }
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if output := os.environ.get("GITHUB_OUTPUT"):
        with Path(output).open("a", encoding="utf-8") as handle:
            handle.write(f"reviewable={str(reviewable).lower()}\n")
    reviewed = sum(result.status == "reviewed" for result in results)
    print(f"reviewable={str(reviewable).lower()} reviewed={reviewed} updates={len(results)} hits={len(hits)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
