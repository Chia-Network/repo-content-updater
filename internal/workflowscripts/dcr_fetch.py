"""Fetch published artifacts for a Dependabot PR and write a review bundle.

The update list (`dependabot/fetch-metadata`) and the PR diff (`gh pr diff`) are
untrusted. Names and versions are validated per ecosystem, passed as argv, and
extracted archives are checked for links and traversal. Writes the artifact
trees, `changes.diff`, `files.txt` and `meta.json` under `DCR_OUT`.
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
    binding_on_added,
    changed_files,
    diff_lines,
    locked_hashes,
    near,
    near_lines,
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
Selector = Callable[[Update, tuple[Candidate, ...], tuple[str, ...], bool], Review]
Precheck = Callable[[Update, tuple[str, ...], tuple[str, ...]], str | None]


@dataclass(frozen=True)
class Ecosystem:
    """One reviewed ecosystem: grammars, review selection and fetcher."""

    name: re.Pattern[str]
    version: re.Pattern[str]
    files: Selector
    fetch: FetchFn
    precheck: Precheck | None = None


def _pypi_index_note(update: Update, added: list[str], removed: list[str]) -> str | None:
    """Reject a package entry whose URLs are not on the public PyPI hosts."""
    for lines in (added, removed):
        for line in near_lines(lines, update.name, INDEX_WINDOW):
            for match in URL_PATTERN.finditer(line):
                parsed = urllib.parse.urlsplit(match.group(0))
                if parsed.scheme != "https" or parsed.hostname not in PYPI_ALLOWED_HOSTS:
                    return "non-default package index"
    return None


def _all_files(_update: Update, candidates: tuple[Candidate, ...], added: list[str], is_new: bool) -> Review:
    """Review every fetched file; only the new side is bound to the lock."""
    if not is_new:
        return Review(candidates)
    bound = bool(candidates) and all(binding_on_added(candidate.binding, added) for candidate in candidates)
    return Review(candidates, bound=bound, note="" if bound else "not bound to the lockfile")


def _safe_label(filename: str) -> str:
    """A single safe path component for one distribution's extraction directory."""
    return re.sub(r"[^A-Za-z0-9._@-]", "_", filename).strip(".") or "artifact"


def _labels(candidates: tuple[Candidate, ...]) -> tuple[Candidate, ...]:
    """Keep several distributions apart by giving each its own extraction directory."""
    if len(candidates) < 2:
        return candidates
    return tuple(replace(candidate, label=_safe_label(candidate.filename)) for candidate in candidates)


def _pypi_files(update: Update, candidates: tuple[Candidate, ...], added: list[str], is_new: bool) -> Review:
    """Review the new distributions whose hashes the lock lists, and check that all are covered."""
    if not is_new:
        chosen = next((candidate for candidate in candidates if candidate.kind == "sdist"), None)
        chosen = chosen or (candidates[0] if candidates else None)
        return Review((chosen,) if chosen else ())
    locked = locked_hashes(update.name, added)
    if not locked:
        return Review(_labels(candidates), note="not bound to the lockfile")
    selected = _labels(tuple(candidate for candidate in candidates if candidate.binding in locked))
    if locked <= {candidate.binding for candidate in candidates}:
        return Review(selected, bound=True)
    return Review(selected, status="unverified", note="partially bound")


ECOSYSTEMS: dict[str, Ecosystem] = {
    "npm_and_yarn": Ecosystem(NPM_NAME, NPM_VERSION, _all_files, fetch_npm),
    "pip": Ecosystem(PIP_NAME, PIP_VERSION, _pypi_files, fetch_pypi, _pypi_index_note),
    "gomod": Ecosystem(GO_NAME, GO_VERSION, _all_files, fetch_gomod),
    "github_actions": Ecosystem(ACTION_NAME, ACTION_SHA, _all_files, fetch_action),
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


def _head_note(update: Update, head_ecosystem: str | None) -> str | None:
    """The fail-closed reason when the head branch does not name the update's ecosystem."""
    if head_ecosystem is None:
        return "head branch does not name the update ecosystem"
    if head_ecosystem != update.ecosystem:
        return "head branch names a different update ecosystem"
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


def _reviewable(update: Update) -> bool:
    """An update in a reviewed ecosystem whose new pin can be fetched and reviewed."""
    if update.ecosystem not in ECOSYSTEMS:
        return False
    return update.ecosystem != "github_actions" or bool(ACTION_SHA.fullmatch(update.new_version))


def _check(update: Update, ecosystem: Ecosystem, added: list[str], removed: list[str]) -> str | None:
    """Return an unverified reason, or None when the update passes the literal checks."""
    if not near(added, update.name, update.new_version, VERSION_WINDOW) or not near(
        removed, update.name, update.prev_version, VERSION_WINDOW
    ):
        return "name and version were not found on the expected diff lines"
    if not ecosystem.name.fullmatch(update.name) or not all(
        ecosystem.version.fullmatch(version) for version in (update.new_version, update.prev_version)
    ):
        return "name or version does not match the ecosystem grammar"
    if ecosystem.precheck is not None and (note := ecosystem.precheck(update, added, removed)):
        return note
    return None


def _process_update(
    index: int,
    update: Update,
    out_dir: Path,
    added: list[str],
    removed: list[str],
    scope_note: str | None = None,
) -> Update:
    ecosystem = ECOSYSTEMS.get(update.ecosystem)
    if ecosystem is None:
        return replace(update, status="not_reviewed", note="ecosystem is not reviewed")
    if update.ecosystem == "github_actions" and not ACTION_SHA.fullmatch(update.new_version):
        return replace(update, status="not_reviewed", note="moving ref: the new pin is not a 40-hex commit SHA")
    if scope_note:
        return replace(update, status="unverified", note=scope_note)
    if note := _check(update, ecosystem, added, removed):
        return replace(update, status="unverified", note=note)
    slug = f"{index:02d}-" + re.sub(r"[^A-Za-z0-9._@-]", "_", f"{update.name}@{update.new_version}")
    try:
        new_review: Review | None = None
        for side, version, is_new in (
            ("old", update.prev_version, False),
            ("new", update.new_version, True),
        ):
            with tempfile.TemporaryDirectory() as tmp:
                candidates = ecosystem.fetch(Path(tmp), update.name, version)
                review = ecosystem.files(update, candidates, added, is_new)
                for candidate in review.candidates:
                    archive = candidate.load()
                    extract(archive, out_dir / side / slug / candidate.label, format_from_name(candidate.filename))
                if is_new:
                    new_review = review
    except (FetchError, OSError) as exc:
        return replace(update, status="fetch_failed", note=str(exc))
    if new_review is None:
        return replace(update, status="fetch_failed", note="the new version was not fetched")
    if new_review.status != "reviewed":
        return replace(update, status=new_review.status, note=new_review.note)
    return replace(update, bound=new_review.bound, note=new_review.note)


def _over_cap(update: Update, head_ecosystem: str | None, scope_note: str | None) -> Update:
    if note := _head_note(update, head_ecosystem):
        return replace(update, status="unverified", note=note)
    status = "unverified" if _reviewable(update) else "not_reviewed"
    note = scope_note if status == "unverified" and scope_note else f"over the {MAX_UPDATES}-update cap"
    return replace(update, status=status, note=note)


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
    for number, line in enumerate(text.splitlines(), 1):
        if not line.startswith("+") or line.startswith("+++"):
            continue
        body = line[1:]
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
    added, removed = diff_lines(diff_text)
    head_ecosystem = _head_ecosystem(os.environ.get("DCR_HEAD_REF", ""))
    scope_note = _scope_note(head_ecosystem, changed_files(diff_text))
    results: list[Update] = []
    for index, update in enumerate(updates[:MAX_UPDATES]):
        note = _head_note(update, head_ecosystem)
        results.append(
            replace(update, status="unverified", note=note)
            if note
            else _process_update(index, update, out_dir, added, removed, scope_note)
        )
    results.extend(_over_cap(update, head_ecosystem, scope_note) for update in updates[MAX_UPDATES:])
    truncated = write_diff(out_dir)
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
