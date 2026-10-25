"""Fetch published artifacts for a Dependabot PR and write a review bundle.

The update list comes from `dependabot/fetch-metadata` and the diff comes from
`gh pr diff`. Both are untrusted input: names and versions are validated against
one grammar per ecosystem, every command receives them as argv, and every
archive is extracted with link and traversal checks.

Outputs, written under `DCR_OUT`:

* `old/<update>/` and `new/<update>/`: extracted published artifacts.
* `changes.diff`: `diff -ruN old new`, capped at 2 MiB.
* `files.txt` and `meta.json`: the full file list and one status per update.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.parse
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
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

NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")
NPM_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
PIP_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
PIP_VERSION = re.compile(
    r"^(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?"
    r"(?:\+[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*)?$",
    re.IGNORECASE,
)
GO_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~/-]*$")
GO_VERSION = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+incompatible)?$")
GO_SUM = re.compile(r"^h1:[A-Za-z0-9+/]{43}=$")
ACTION_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
ACTION_SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
BIDI_CONTROL = re.compile(r"[\u202a-\u202e\u2066-\u2069]")


class FetchError(Exception):
    """A fetch, download, validation or extraction step could not complete."""


class Unverified(Exception):
    """An update's name, version or position in the diff could not be checked."""


@dataclass(frozen=True)
class Update:
    """One dependency update reported by fetch-metadata."""

    name: str
    ecosystem: str
    directory: str
    prev_version: str
    new_version: str


@dataclass(frozen=True)
class Fetched:
    """A downloaded artifact plus the hash that should bind it to the lockfile."""

    archive: Path
    binding: str


@dataclass
class UpdateResult:
    """Per-update review status written to meta.json."""

    update: Update
    status: str = "reviewed"
    bound: bool = False
    note: str = ""

    def as_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-ready view of this update."""
        return {
            "name": self.update.name,
            "ecosystem": self.update.ecosystem,
            "directory": self.update.directory,
            "prev_version": self.update.prev_version,
            "new_version": self.update.new_version,
            "status": self.status,
            "bound": self.bound,
            "note": self.note,
        }


@dataclass(frozen=True)
class Ecosystem:
    """One reviewed ecosystem: its version grammar and native fetcher."""

    version_pattern: re.Pattern[str]
    fetch: Callable[[Path, str, str], Fetched]
    name_ok: Callable[[str], bool]


def _valid_npm_name(name: str) -> bool:
    return len(name) <= 214 and bool(NPM_NAME.fullmatch(name))


def _valid_pip_name(name: str) -> bool:
    return len(name) <= 214 and bool(PIP_NAME.fullmatch(name))


def _valid_go_name(name: str) -> bool:
    if len(name) > 300 or not GO_NAME.fullmatch(name):
        return False
    parts = name.split("/")
    return all(part and part not in {".", ".."} for part in parts)


def _valid_action_name(name: str) -> bool:
    return bool(ACTION_NAME.fullmatch(name))


def _run(
    args: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    text: bool = True,
) -> subprocess.CompletedProcess:
    """Run one argv list without a shell and fail on a non-zero exit."""
    proc = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=text,
    )
    if proc.returncode != 0:
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
            length = response.headers.get("Content-Length")
            if length is not None and int(length) > limit:
                raise FetchError("download exceeds the size cap")
            data = response.read(limit + 1)
    except FetchError:
        raise
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise FetchError(f"download failed: {exc}") from exc
    if len(data) > limit:
        raise FetchError("download exceeds the size cap")
    return data


def _fetch_npm(work: Path, name: str, version: str) -> Fetched:
    _run(["npm", "pack", "--ignore-scripts", f"{name}@{version}"], cwd=work)
    archives = sorted(work.glob("*.tgz"))
    if len(archives) != 1:
        raise FetchError("npm pack did not produce exactly one archive")
    data = archives[0].read_bytes()
    binding = "sha512-" + base64.b64encode(sha512(data).digest()).decode("ascii")
    return Fetched(archives[0], binding)


def _select_pypi_file(files: object) -> dict[str, object]:
    if not isinstance(files, list):
        raise FetchError("PyPI response has no file list")
    usable = [item for item in files if isinstance(item, dict) and isinstance(item.get("url"), str)]
    for kind in ("sdist", "bdist_wheel"):
        for item in usable:
            if item.get("packagetype") == kind:
                return item
    if usable:
        return usable[0]
    raise FetchError("PyPI response has no downloadable file")


def _fetch_pypi(work: Path, name: str, version: str) -> Fetched:
    endpoint = f"https://pypi.org/pypi/{urllib.parse.quote(name, safe='')}/{urllib.parse.quote(version, safe='')}/json"
    try:
        payload = json.loads(_read_url(endpoint, MAX_PYPI_JSON, PYPI_HOSTS))
    except json.JSONDecodeError as exc:
        raise FetchError("PyPI JSON could not be parsed") from exc
    chosen = _select_pypi_file(payload.get("urls") if isinstance(payload, dict) else None)
    url = chosen["url"]
    if not isinstance(url, str):
        raise FetchError("PyPI file URL is missing")
    data = _read_url(url, MAX_BYTES, PYPI_DOWNLOAD_HOSTS)
    digests = chosen.get("digests")
    expected = digests.get("sha256") if isinstance(digests, dict) else None
    actual = sha256(data).hexdigest()
    if not isinstance(expected, str) or not SHA256_HEX.fullmatch(expected) or expected != actual:
        raise FetchError("downloaded file does not match the PyPI sha256 digest")
    archive = work / "package"
    archive.write_bytes(data)
    return Fetched(archive, f"sha256:{actual}")


def _fetch_gomod(work: Path, name: str, version: str) -> Fetched:
    env = {
        **os.environ,
        "GO111MODULE": "on",
        "GOWORK": "off",
        "GOFLAGS": "",
        "GONOSUMDB": "",
        "GOPRIVATE": "",
        "GOSUMDB": "sum.golang.org",
    }
    proc = _run(["go", "mod", "download", "-json", f"{name}@{version}"], cwd=work, env=env)
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise FetchError("go mod download did not return JSON") from exc
    zip_name = payload.get("Zip") if isinstance(payload, dict) else None
    sum_value = payload.get("Sum") if isinstance(payload, dict) else None
    if not isinstance(zip_name, str) or not isinstance(sum_value, str) or not GO_SUM.fullmatch(sum_value):
        raise FetchError("go mod download did not return a zip and an h1 sum")
    archive = Path(zip_name)
    if not archive.is_file():
        raise FetchError("go module zip is missing")
    return Fetched(archive, sum_value)


def _fetch_action(work: Path, name: str, version: str) -> Fetched:
    repo = work / "repo"
    repo.mkdir()
    _run(["git", "init", "-q"], cwd=repo)
    remote = f"https://github.com/{name}"
    _run(["git", "-C", str(repo), "fetch", "--depth", "1", remote, version], cwd=work)
    proc = _run(["git", "-C", str(repo), "archive", "--format=tar", "FETCH_HEAD"], cwd=work, text=False)
    archive = work / "action.tar"
    archive.write_bytes(proc.stdout)
    return Fetched(archive, version)


ECOSYSTEMS: dict[str, Ecosystem] = {
    "npm_and_yarn": Ecosystem(NPM_VERSION, _fetch_npm, _valid_npm_name),
    "pip": Ecosystem(PIP_VERSION, _fetch_pypi, _valid_pip_name),
    "gomod": Ecosystem(GO_VERSION, _fetch_gomod, _valid_go_name),
    "github_actions": Ecosystem(ACTION_SHA, _fetch_action, _valid_action_name),
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
        if not isinstance(item, dict):
            raise SystemExit("every updated dependency must be an object")
        fields = {}
        for key in ("dependencyName", "packageEcosystem", "prevVersion", "newVersion"):
            value = item.get(key)
            if not isinstance(value, str) or not value:
                raise SystemExit(f"updated dependency is missing {key}")
            fields[key] = value
        directory = item.get("directory", "")
        updates.append(
            Update(
                name=fields["dependencyName"],
                ecosystem=fields["packageEcosystem"],
                directory=directory if isinstance(directory, str) else "",
                prev_version=fields["prevVersion"],
                new_version=fields["newVersion"],
            ),
        )
    return updates


def _diff_lines(text: str) -> tuple[list[str], list[str]]:
    added: list[str] = []
    removed: list[str] = []
    for line in text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            removed.append(line[1:])
    return added, removed


def _present(update: Update, added: list[str], removed: list[str]) -> bool:
    in_added = any(update.name in line and update.new_version in line for line in added)
    in_removed = any(update.prev_version in line for line in removed)
    return in_added and in_removed


def _validate(update: Update, ecosystem: Ecosystem) -> None:
    if not ecosystem.name_ok(update.name) or not ecosystem.version_pattern.fullmatch(update.new_version):
        raise Unverified("name or version does not match the ecosystem grammar")
    if not ecosystem.version_pattern.fullmatch(update.prev_version):
        raise Unverified("previous version does not match the ecosystem grammar")


def _tar_members_ok(members: list[tarfile.TarInfo]) -> None:
    total = 0
    for member in members:
        if member.isdir():
            continue
        if not member.isfile():
            raise FetchError("archive contains a link or a non-regular entry")
        total += member.size
        if total > MAX_BYTES:
            raise FetchError("archive exceeds the extracted byte cap")


def _extract_tar(archive: Path, dest: Path) -> None:
    try:
        with tarfile.open(archive, "r:*") as handle:
            members = handle.getmembers()
            if len(members) > MAX_FILES:
                raise FetchError("archive exceeds the file-count cap")
            _tar_members_ok(members)
            handle.extractall(dest, filter="data")
    except FetchError:
        raise
    except (tarfile.TarError, OSError) as exc:
        raise FetchError(f"tar extraction failed: {exc}") from exc


def _zip_infos_ok(infos: list[zipfile.ZipInfo]) -> None:
    if len(infos) > MAX_FILES:
        raise FetchError("archive exceeds the file-count cap")
    total = 0
    for info in infos:
        name = info.filename
        parts = PurePosixPath(name).parts
        if not parts or name.startswith(("/", "\\")) or "\\" in name or ".." in parts or re.match(r"^[A-Za-z]:", name):
            raise FetchError("archive contains an unsafe path")
        if stat.S_ISLNK((info.external_attr >> 16) & 0o170000):
            raise FetchError("archive contains a symlink")
        if info.is_dir():
            continue
        total += info.file_size
        if total > MAX_BYTES:
            raise FetchError("archive exceeds the extracted byte cap")


def _extract_zip(archive: Path, dest: Path) -> None:
    try:
        with zipfile.ZipFile(archive) as handle:
            infos = handle.infolist()
            _zip_infos_ok(infos)
            for info in infos:
                target = dest.joinpath(*PurePosixPath(info.filename).parts)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with handle.open(info) as source, target.open("wb") as sink:
                    shutil.copyfileobj(source, sink)
    except FetchError:
        raise
    except (zipfile.BadZipFile, OSError) as exc:
        raise FetchError(f"zip extraction failed: {exc}") from exc


def _extract(archive: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    if zipfile.is_zipfile(archive):
        _extract_zip(archive, dest)
    else:
        _extract_tar(archive, dest)


def _slug(index: int, update: Update) -> str:
    raw = f"{update.name}@{update.new_version}"
    return f"{index:02d}-" + re.sub(r"[^A-Za-z0-9._@-]", "_", raw)


def _fetch_and_extract(update: Update, version: str, dest: Path, ecosystem: Ecosystem) -> Fetched:
    with tempfile.TemporaryDirectory() as tmp:
        fetched = ecosystem.fetch(Path(tmp), update.name, version)
        _extract(fetched.archive, dest)
    return fetched


def _process_update(
    index: int,
    update: Update,
    out_dir: Path,
    added: list[str],
    removed: list[str],
) -> UpdateResult:
    result = UpdateResult(update)
    ecosystem = ECOSYSTEMS.get(update.ecosystem)
    if ecosystem is None:
        result.status = "not_reviewed"
        result.note = "ecosystem is not reviewed"
        return result
    if update.ecosystem == "github_actions" and not ACTION_SHA.fullmatch(update.new_version):
        result.status = "not_reviewed"
        result.note = "moving ref: the new pin is not a 40-hex commit SHA"
        return result
    if not _present(update, added, removed):
        result.status = "unverified"
        result.note = "name and version were not found on the expected diff lines"
        return result
    try:
        _validate(update, ecosystem)
        if update.ecosystem == "github_actions" and not ACTION_SHA.fullmatch(update.prev_version):
            raise Unverified("previous action version is not a 40-hex commit SHA")
        slug = _slug(index, update)
        _fetch_and_extract(update, update.prev_version, out_dir / "old" / slug, ecosystem)
        fetched = _fetch_and_extract(update, update.new_version, out_dir / "new" / slug, ecosystem)
    except Unverified as exc:
        result.status = "unverified"
        result.note = str(exc)
        return result
    except (FetchError, OSError) as exc:
        result.status = "fetch_failed"
        result.note = str(exc)
        return result
    result.bound = any(fetched.binding in line for line in added)
    if not result.bound:
        result.note = "not bound to the lockfile"
    return result


def _write_diff(out_dir: Path) -> bool:
    (out_dir / "old").mkdir(exist_ok=True)
    (out_dir / "new").mkdir(exist_ok=True)
    try:
        proc = subprocess.run(
            ["diff", "-ruN", "old", "new"],
            cwd=out_dir,
            check=False,
            capture_output=True,
            text=False,
        )
    except OSError as exc:
        raise FetchError(f"diff failed: {exc}") from exc
    if proc.returncode not in {0, 1}:
        detail = proc.stderr if isinstance(proc.stderr, bytes) else proc.stderr.encode()
        raise FetchError(f"diff exited {proc.returncode}: {detail.decode('utf-8', 'replace').strip()[:500]}")
    data = proc.stdout
    truncated = len(data) > MAX_DIFF_BYTES
    if truncated:
        data = data[:MAX_DIFF_BYTES] + b"\n[changes.diff truncated at 2 MiB]\n"
    (out_dir / "changes.diff").write_text(data.decode("utf-8", "replace"), encoding="utf-8")
    return truncated


def _write_file_list(out_dir: Path) -> list[str]:
    excluded = {"meta.json", "changes.diff", "files.txt"}
    paths: list[str] = []
    for path in out_dir.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(out_dir).as_posix()
        if relative not in excluded:
            paths.append(relative)
    paths.sort()
    (out_dir / "files.txt").write_text("\n".join(paths) + ("\n" if paths else ""), encoding="utf-8")
    return paths


def _ioc_patterns() -> list[tuple[str, re.Pattern[str]]]:
    raw = os.environ.get("DEPENDABOT_CURSOR_MALWARE_IOC_PATTERNS", "")
    try:
        patterns = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit("DEPENDABOT_CURSOR_MALWARE_IOC_PATTERNS is not valid JSON") from exc
    if not isinstance(patterns, list) or not patterns:
        raise SystemExit("DEPENDABOT_CURSOR_MALWARE_IOC_PATTERNS must be a non-empty list")
    compiled: list[tuple[str, re.Pattern[str]]] = []
    for pattern in patterns:
        if not isinstance(pattern, str) or not pattern:
            raise SystemExit("every IOC pattern must be a non-empty string")
        try:
            compiled.append((pattern, re.compile(pattern)))
        except re.error as exc:
            raise SystemExit(f"IOC pattern {pattern!r} is not a valid regex") from exc
    return compiled


def _scan_diff(path: Path, patterns: list[tuple[str, re.Pattern[str]]]) -> list[dict[str, object]]:
    hits: list[dict[str, object]] = []
    text = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
    for number, line in enumerate(text.splitlines(), 1):
        if not line.startswith("+") or line.startswith("+++"):
            continue
        body = line[1:]
        for source, pattern in patterns:
            match = pattern.search(body)
            if match is not None:
                hits.append({"kind": "ioc", "pattern": source, "line": number, "match": match.group(0)[:80]})
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
    results.extend(
        UpdateResult(update, "not_reviewed", note=f"over the {MAX_UPDATES}-update cap")
        for update in updates[MAX_UPDATES:]
    )

    truncated = _write_diff(out_dir)
    if truncated:
        for result in results:
            if result.status == "reviewed":
                result.status = "truncated"
                result.note = "changes.diff exceeded the 2 MiB cap"

    file_list = _write_file_list(out_dir)
    hits = _scan_diff(out_dir / "changes.diff", patterns)
    meta = {
        "schema": 1,
        "max_updates": MAX_UPDATES,
        "truncated": truncated,
        "updates": [result.as_dict() for result in results],
        "ioc_hits": hits,
        "files": file_list,
    }
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    reviewed = sum(result.status == "reviewed" for result in results)
    print(f"reviewed={reviewed} updates={len(results)} hits={len(hits)} truncated={str(truncated).lower()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
