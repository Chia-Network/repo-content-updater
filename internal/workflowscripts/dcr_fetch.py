"""Fetch published artifacts for a Dependabot PR and write a review bundle.

The update list (`dependabot/fetch-metadata`) and the PR diff (`gh pr diff`) are
untrusted. Names and versions are validated per ecosystem, passed as argv, and
extracted archives are checked for links and traversal. Writes the artifact
trees, `changes.diff`, `files.txt` and `meta.json` under `DCR_OUT`.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import tarfile
import tempfile
import urllib.parse
import zipfile
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from hashlib import sha256, sha512
from pathlib import Path, PurePosixPath
from urllib.request import urlopen as _urlopen

MAX_UPDATES = 10
MAX_FILES = 5000
MAX_BYTES = 100 * 1024 * 1024
MAX_DIFF_BYTES = 2 * 1024 * 1024
MAX_PYPI_JSON = 5 * 1024 * 1024
PYPI_HOSTS = frozenset({"pypi.org"})
PYPI_DOWNLOAD_HOSTS = frozenset({"files.pythonhosted.org"})
PYPI_ALLOWED_HOSTS = PYPI_HOSTS | PYPI_DOWNLOAD_HOSTS
PYPI_DISTRIBUTIONS = frozenset({"sdist", "bdist_wheel"})
UPDATE_FIELDS = ("dependencyName", "packageEcosystem", "prevVersion", "newVersion")
VERSION_WINDOW = 3
HASH_WINDOW = 24
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
GO_SUM = re.compile(r"^h1:[A-Za-z0-9+/]{43}=$")
ACTION_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
ACTION_SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
SHA256_VALUE = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")
BIDI_CONTROL = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
UNSAFE_ZIP_PATH = re.compile(r"^(?:[A-Za-z]:|[\\/])|[\\]|(?:^|/)\.\.(?:/|$)")
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")

NAME_CHARS = r"A-Za-z0-9._~-"
VERSION_CHARS = r"A-Za-z0-9._+-"
BINDING_CHARS = r"A-Za-z0-9._~+/=-"
ZIP_SUFFIXES = frozenset({".zip", ".whl", ".egg"})


class FetchError(Exception):
    """A fetch, download, validation or extraction step could not complete."""


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
class Candidate:
    """A release file that can be loaded, with the literal that binds it to the lock."""

    filename: str
    binding: str
    load: Callable[[], Path]
    kind: str = ""
    label: str = ""


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
    """One reviewed ecosystem: grammars, archive format, review selection and fetcher."""

    name: re.Pattern[str]
    version: re.Pattern[str]
    archive_format: Callable[[str], str]
    files: Selector
    fetch: FetchFn
    precheck: Precheck | None = None


def _run(
    args: list[str], *, cwd: Path, env: dict[str, str] | None = None, text: bool = True, ok: tuple[int, ...] = (0,)
) -> subprocess.CompletedProcess:
    """Run one argv list without a shell and fail on an unexpected exit."""
    try:
        proc = subprocess.run(args, cwd=cwd, env=env, check=False, capture_output=True, text=text)
    except OSError as exc:
        raise FetchError(f"{args[0]} could not run: {exc}") from exc
    if proc.returncode not in ok:
        detail = proc.stderr if isinstance(proc.stderr, str) else proc.stderr.decode("utf-8", "replace")
        raise FetchError(f"{args[0]} exited {proc.returncode}: {detail.strip()[:500]}")
    return proc


def _read_url(url: str, limit: int, hosts: frozenset[str]) -> bytes:
    """Read one HTTPS URL from an expected host, refusing anything above the byte cap."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in hosts:
        raise FetchError("download URL is not on the expected host")
    try:
        with _urlopen(url, timeout=30) as response:  # ruff: ignore[suspicious-url-open-usage] - scheme and host checked above
            data = response.read(limit + 1)
    except (OSError, ValueError) as exc:
        raise FetchError(f"download failed: {exc}") from exc
    if len(data) > limit:
        raise FetchError("download exceeds the size cap")
    return data


def _token(text: str, chars: str) -> re.Pattern[str]:
    """A literal match that cannot start or end inside a longer token."""
    return re.compile(rf"(?<![{chars}]){re.escape(text)}(?![{chars}])")


def _near(lines: list[str], anchor: str, needle: str, window: int) -> bool:
    """True when `needle` appears within `window` lines of a whole-token `anchor`."""
    anchor_pattern = _token(anchor, NAME_CHARS)
    needle_pattern = _token(needle, VERSION_CHARS)
    for index, line in enumerate(lines):
        if not anchor_pattern.search(line):
            continue
        nearby = lines[max(0, index - window) : index + window + 1]
        if any(needle_pattern.search(candidate) for candidate in nearby):
            return True
    return False


def _near_lines(lines: list[str], anchor: str, window: int) -> list[str]:
    """The lines within `window` of a whole-token `anchor`, in original order."""
    anchor_pattern = _token(anchor, NAME_CHARS)
    indexes = {index for index, line in enumerate(lines) if anchor_pattern.search(line)}
    selected: set[int] = set()
    for index in indexes:
        selected.update(range(max(0, index - window), min(len(lines), index + window + 1)))
    return [lines[index] for index in sorted(selected)]


def _binding_on_added(binding: str, added: list[str]) -> bool:
    if not binding:
        return False
    pattern = _token(binding, BINDING_CHARS)
    return any(pattern.search(line) for line in added)


def _locked_hashes(update: Update, added: list[str]) -> frozenset[str]:
    """The sha256 values the lock lists near this package's entry."""
    return frozenset(
        match.group(0) for line in _near_lines(added, update.name, HASH_WINDOW) for match in SHA256_VALUE.finditer(line)
    )


def _pypi_index_note(update: Update, added: list[str], removed: list[str]) -> str | None:
    """Reject a package entry whose URLs are not on the public PyPI hosts."""
    for lines in (added, removed):
        for line in _near_lines(lines, update.name, INDEX_WINDOW):
            for match in URL_PATTERN.finditer(line):
                parsed = urllib.parse.urlsplit(match.group(0))
                if parsed.scheme != "https" or parsed.hostname not in PYPI_ALLOWED_HOSTS:
                    return "non-default package index"
    return None


def _all_files(_update: Update, candidates: tuple[Candidate, ...], added: list[str], is_new: bool) -> Review:
    """Review every fetched file; only the new side is bound to the lock."""
    if not is_new:
        return Review(candidates)
    bound = bool(candidates) and all(_binding_on_added(candidate.binding, added) for candidate in candidates)
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
    locked = _locked_hashes(update, added)
    if not locked:
        return Review(_labels(candidates), note="not bound to the lockfile")
    selected = _labels(tuple(candidate for candidate in candidates if _binding_on_added(candidate.binding, added)))
    if {candidate.binding for candidate in candidates} >= locked:
        return Review(selected, bound=True)
    return Review(selected, status="unverified", note="partially bound")


def _fetch_npm(work: Path, name: str, version: str) -> tuple[Candidate, ...]:
    _run(["npm", "pack", "--ignore-scripts", f"{name}@{version}"], cwd=work)
    archives = sorted(work.glob("*.tgz"))
    if len(archives) != 1:
        raise FetchError("npm pack did not produce exactly one archive")
    archive = archives[0]
    data = archive.read_bytes()
    binding = "sha512-" + base64.b64encode(sha512(data).digest()).decode("ascii")
    return (Candidate(archive.name, binding, lambda: archive),)


def _fetch_pypi(work: Path, name: str, version: str) -> tuple[Candidate, ...]:
    endpoint = f"https://pypi.org/pypi/{urllib.parse.quote(name, safe='')}/{urllib.parse.quote(version, safe='')}/json"
    try:
        payload = json.loads(_read_url(endpoint, MAX_PYPI_JSON, PYPI_HOSTS))
    except json.JSONDecodeError as exc:
        raise FetchError("PyPI JSON could not be parsed") from exc
    files = payload.get("urls") if isinstance(payload, dict) else None
    if not isinstance(files, list):
        raise FetchError("PyPI response has no file list")
    usable = [
        item
        for item in files
        if isinstance(item, dict) and isinstance(item.get("url"), str) and item.get("packagetype") in PYPI_DISTRIBUTIONS
    ]
    if not usable:
        raise FetchError("PyPI response has no downloadable distribution")
    candidates: list[Candidate] = []
    for index, item in enumerate(usable):
        filename = item.get("filename")
        digests = item.get("digests")
        expected = digests.get("sha256") if isinstance(digests, dict) else None
        if (
            not isinstance(filename, str)
            or not filename
            or not isinstance(expected, str)
            or not SHA256_HEX.fullmatch(expected)
        ):
            raise FetchError("PyPI distribution is missing a filename or sha256 digest")
        path = work / f"dist-{index:02d}"
        url = str(item["url"])
        kind = str(item.get("packagetype", ""))

        def load(path: Path = path, url: str = url, expected: str = expected) -> Path:
            data = _read_url(url, MAX_BYTES, PYPI_DOWNLOAD_HOSTS)
            actual = sha256(data).hexdigest()
            if actual != expected:
                raise FetchError("downloaded file does not match the PyPI sha256 digest")
            path.write_bytes(data)
            return path

        candidates.append(Candidate(filename, expected, load, kind=kind))
    return tuple(candidates)


def _fetch_gomod(work: Path, name: str, version: str) -> tuple[Candidate, ...]:
    env = dict(
        os.environ, GO111MODULE="on", GOWORK="off", GOFLAGS="", GONOSUMDB="", GOPRIVATE="", GOSUMDB="sum.golang.org"
    )
    try:
        payload = json.loads(_run(["go", "mod", "download", "-json", f"{name}@{version}"], cwd=work, env=env).stdout)
    except json.JSONDecodeError as exc:
        raise FetchError("go mod download did not return JSON") from exc
    zip_name = payload.get("Zip") if isinstance(payload, dict) else None
    sum_value = payload.get("Sum") if isinstance(payload, dict) else None
    if not isinstance(zip_name, str) or not isinstance(sum_value, str) or not GO_SUM.fullmatch(sum_value):
        raise FetchError("go mod download did not return a zip and an h1 sum")
    archive = Path(zip_name)
    return (Candidate(archive.name, sum_value, lambda: archive, kind="zip"),)


def _fetch_action(work: Path, name: str, version: str) -> tuple[Candidate, ...]:
    _run(["git", "init", "-q", "repo"], cwd=work)
    _run(["git", "-C", "repo", "fetch", "--depth", "1", f"https://github.com/{name}", version], cwd=work)
    attributes = work / "repo" / ".git" / "info" / "attributes"
    attributes.parent.mkdir(parents=True, exist_ok=True)
    attributes.write_text("* -export-ignore -export-subst\n", encoding="utf-8")
    archive = work / "action.tar"
    archive.write_bytes(
        _run(["git", "-C", "repo", "archive", "--format=tar", "FETCH_HEAD"], cwd=work, text=False).stdout
    )
    return (Candidate(archive.name, version, lambda: archive),)


def _tar_format(_filename: str) -> str:
    return "tar"


def _zip_format(_filename: str) -> str:
    return "zip"


def _format_from_name(filename: str) -> str:
    return "zip" if PurePosixPath(filename).suffix.lower() in ZIP_SUFFIXES else "tar"


ECOSYSTEMS: dict[str, Ecosystem] = {
    "npm_and_yarn": Ecosystem(NPM_NAME, NPM_VERSION, _tar_format, _all_files, _fetch_npm),
    "pip": Ecosystem(PIP_NAME, PIP_VERSION, _format_from_name, _pypi_files, _fetch_pypi, _pypi_index_note),
    "gomod": Ecosystem(GO_NAME, GO_VERSION, _zip_format, _all_files, _fetch_gomod),
    "github_actions": Ecosystem(ACTION_NAME, ACTION_SHA, _tar_format, _all_files, _fetch_action),
}


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
        updates.append(Update(*values[:2], directory if isinstance(directory, str) else "", *values[2:]))
    return updates


def _diff_lines(text: str) -> tuple[list[str], list[str]]:
    lines = text.splitlines()
    return (
        [line[1:] for line in lines if line.startswith("+") and not line.startswith("+++")],
        [line[1:] for line in lines if line.startswith("-") and not line.startswith("---")],
    )


def _reviewable(update: Update) -> bool:
    """An update in a reviewed ecosystem whose new pin can be fetched and reviewed."""
    if update.ecosystem not in ECOSYSTEMS:
        return False
    return update.ecosystem != "github_actions" or bool(ACTION_SHA.fullmatch(update.new_version))


def _check(update: Update, ecosystem: Ecosystem, added: list[str], removed: list[str]) -> str | None:
    """Return an unverified reason, or None when the update passes the literal checks."""
    if not _near(added, update.name, update.new_version, VERSION_WINDOW) or not _near(
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


def _check_budget(count: int, total: int) -> None:
    if count > MAX_FILES:
        raise FetchError("archive exceeds the file-count cap")
    if total > MAX_BYTES:
        raise FetchError("archive exceeds the extracted byte cap")


def _extract(archive: Path, dest: Path, archive_format: str | None = None) -> None:
    """Extract using the stated archive format, or a filename suffix when none is passed."""
    archive_format = archive_format or _format_from_name(archive.name)
    dest.mkdir(parents=True, exist_ok=True)
    try:
        if archive_format == "zip":
            with zipfile.ZipFile(archive) as handle:
                infos = handle.infolist()
                if any(not info.filename or UNSAFE_ZIP_PATH.search(info.filename) for info in infos):
                    raise FetchError("archive contains an unsafe path")
                if any((info.external_attr >> 16) & 0o170000 == 0o120000 for info in infos):
                    raise FetchError("archive contains a symlink")
                _check_budget(len(infos), sum(info.file_size for info in infos if not info.is_dir()))
                handle.extractall(dest)  # ruff: ignore[tarfile-unsafe-members] - names, links and size checked above
        elif archive_format == "tar":
            with tarfile.open(archive, "r:*") as handle:
                members = handle.getmembers()
                _check_budget(len(members), sum(member.size for member in members if not member.isdir()))
                handle.extractall(dest, filter="data")
        else:
            raise FetchError(f"unsupported archive format: {archive_format}")
    except (tarfile.TarError, zipfile.BadZipFile, OSError) as exc:
        raise FetchError(f"extraction failed: {exc}") from exc


def _process_update(index: int, update: Update, out_dir: Path, added: list[str], removed: list[str]) -> Update:
    ecosystem = ECOSYSTEMS.get(update.ecosystem)
    if ecosystem is None:
        return replace(update, status="not_reviewed", note="ecosystem is not reviewed")
    if update.ecosystem == "github_actions" and not ACTION_SHA.fullmatch(update.new_version):
        return replace(update, status="not_reviewed", note="moving ref: the new pin is not a 40-hex commit SHA")
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
                    _extract(
                        archive, out_dir / side / slug / candidate.label, ecosystem.archive_format(candidate.filename)
                    )
                if is_new:
                    new_review = review
    except (FetchError, OSError) as exc:
        return replace(update, status="fetch_failed", note=str(exc))
    if new_review is None:
        return replace(update, status="fetch_failed", note="the new version was not fetched")
    if new_review.status != "reviewed":
        return replace(update, status=new_review.status, note=new_review.note)
    return replace(update, bound=new_review.bound, note=new_review.note)


def _over_cap(update: Update) -> Update:
    status = "unverified" if _reviewable(update) else "not_reviewed"
    return replace(update, status=status, note=f"over the {MAX_UPDATES}-update cap")


def _write_diff(out_dir: Path) -> bool:
    (out_dir / "old").mkdir(exist_ok=True)
    (out_dir / "new").mkdir(exist_ok=True)
    data = _run(["diff", "-ruN", "old", "new"], cwd=out_dir, text=False, ok=(0, 1)).stdout
    truncated = len(data) > MAX_DIFF_BYTES
    if truncated:
        data = data[:MAX_DIFF_BYTES] + b"\n[changes.diff truncated at 2 MiB]\n"
    (out_dir / "changes.diff").write_text(data.decode("utf-8", "replace"), encoding="utf-8")
    return truncated


def _write_file_list(out_dir: Path) -> list[str]:
    paths = sorted(path.relative_to(out_dir).as_posix() for path in out_dir.rglob("*") if path.is_file())
    paths = [path for path in paths if path not in {"meta.json", "changes.diff", "files.txt"}]
    (out_dir / "files.txt").write_text("\n".join(paths) + ("\n" if paths else ""), encoding="utf-8")
    return paths


def _ioc_patterns() -> list[tuple[str, re.Pattern[str]]]:
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


def _scan_diff(path: Path, patterns: list[tuple[str, re.Pattern[str]]]) -> list[dict[str, object]]:
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
    patterns = _ioc_patterns()
    updates = _parse_updates(os.environ.get("UPDATED_DEPENDENCIES_JSON", ""))
    diff_text = Path(os.environ["PR_DIFF_PATH"]).read_text(encoding="utf-8", errors="replace")
    added, removed = _diff_lines(diff_text)
    results = [
        _process_update(index, update, out_dir, added, removed) for index, update in enumerate(updates[:MAX_UPDATES])
    ]
    results.extend(_over_cap(update) for update in updates[MAX_UPDATES:])
    truncated = _write_diff(out_dir)
    if truncated:
        results = [
            replace(result, status="truncated", note="changes.diff exceeded the 2 MiB cap")
            if result.status == "reviewed"
            else result
            for result in results
        ]
    file_list = _write_file_list(out_dir)
    hits = _scan_diff(out_dir / "changes.diff", patterns)
    meta = {
        "schema": 1,
        "max_updates": MAX_UPDATES,
        "truncated": truncated,
        "updates": [asdict(result) for result in results],
        "ioc_hits": hits,
        "files": file_list,
    }
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    reviewed = sum(result.status == "reviewed" for result in results)
    print(f"reviewed={reviewed} updates={len(results)} hits={len(hits)} truncated={str(truncated).lower()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
