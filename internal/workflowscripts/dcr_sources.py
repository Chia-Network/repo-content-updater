"""Fetch native artifacts and extract them without links or unbounded output.

Every source and archive is untrusted. Commands run as argv lists, downloads
come only from the expected hosts and are capped, and an archive is rejected
when a member is a link, has a traversal path, or exceeds the size caps.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import tarfile
import urllib.parse
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256, sha512
from pathlib import Path, PurePosixPath
from urllib.request import urlopen as _urlopen

MAX_FILES = 5000
MAX_BYTES = 100 * 1024 * 1024
MAX_PYPI_JSON = 5 * 1024 * 1024
PYPI_HOSTS = frozenset({"pypi.org"})
PYPI_DOWNLOAD_HOSTS = frozenset({"files.pythonhosted.org"})
PYPI_ALLOWED_HOSTS = PYPI_HOSTS | PYPI_DOWNLOAD_HOSTS
PYPI_DISTRIBUTIONS = frozenset({"sdist", "bdist_wheel"})
GO_SUM = re.compile(r"^h1:[A-Za-z0-9+/]{43}=$")
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
UNSAFE_ZIP_PATH = re.compile(r"^(?:[A-Za-z]:|[\\/])|[\\]|(?:^|/)\.\.(?:/|$)")
ZIP_SUFFIXES = frozenset({".zip", ".whl", ".egg"})


class FetchError(Exception):
    """A fetch, download, validation or extraction step could not complete."""


@dataclass(frozen=True)
class Candidate:
    """A release file that can be loaded, with the literal that binds it to the lock."""

    filename: str
    binding: str
    load: Callable[[], Path]
    kind: str = ""
    label: str = ""


def format_from_name(filename: str) -> str:
    """The archive format implied by a filename suffix."""
    return "zip" if PurePosixPath(filename).suffix.lower() in ZIP_SUFFIXES else "tar"


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


def fetch_npm(work: Path, name: str, version: str) -> tuple[Candidate, ...]:
    """Pack one npm release with lifecycle scripts disabled."""
    _run(["npm", "pack", "--ignore-scripts", f"{name}@{version}"], cwd=work)
    archives = sorted(work.glob("*.tgz"))
    if len(archives) != 1:
        raise FetchError("npm pack did not produce exactly one archive")
    archive = archives[0]
    binding = "sha512-" + base64.b64encode(sha512(archive.read_bytes()).digest()).decode("ascii")
    return (Candidate(archive.name, binding, lambda: archive),)


def fetch_pypi(work: Path, name: str, version: str) -> tuple[Candidate, ...]:
    """Read the PyPI JSON file list, then download files only from the file host."""
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


def fetch_gomod(work: Path, name: str, version: str) -> tuple[Candidate, ...]:
    """Download one Go module, verified against the checksum database."""
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


def fetch_action(work: Path, name: str, version: str) -> tuple[Candidate, ...]:
    """Fetch one action commit and archive it with upstream export rules disabled."""
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


def _check_budget(count: int, total: int) -> None:
    if count > MAX_FILES:
        raise FetchError("archive exceeds the file-count cap")
    if total > MAX_BYTES:
        raise FetchError("archive exceeds the extracted byte cap")


def extract(archive: Path, dest: Path, archive_format: str | None = None) -> None:
    """Extract using the stated archive format, or a filename suffix when none is passed."""
    archive_format = archive_format or format_from_name(archive.name)
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
