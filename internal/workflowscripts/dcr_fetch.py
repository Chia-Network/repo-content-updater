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
from pathlib import Path
from urllib.request import urlopen as _urlopen

MAX_UPDATES = 10
MAX_FILES = 5000
MAX_BYTES = 100 * 1024 * 1024
MAX_DIFF_BYTES = 2 * 1024 * 1024
MAX_PYPI_JSON = 5 * 1024 * 1024
PYPI_HOSTS = frozenset({"pypi.org"})
PYPI_DOWNLOAD_HOSTS = frozenset({"files.pythonhosted.org"})
UPDATE_FIELDS = ("dependencyName", "packageEcosystem", "prevVersion", "newVersion")

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
BIDI_CONTROL = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
UNSAFE_ZIP_PATH = re.compile(r"^(?:[A-Za-z]:|[\\/])|[\\]|(?:^|/)\.\.(?:/|$)")


class FetchError(Exception):
    """A fetch, download, validation or extraction step could not complete."""


Ecosystem = tuple[re.Pattern[str], re.Pattern[str], Callable[[Path, str, str], tuple[Path, str]]]


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


def _fetch_npm(work: Path, name: str, version: str) -> tuple[Path, str]:
    _run(["npm", "pack", "--ignore-scripts", f"{name}@{version}"], cwd=work)
    archives = sorted(work.glob("*.tgz"))
    if len(archives) != 1:
        raise FetchError("npm pack did not produce exactly one archive")
    data = archives[0].read_bytes()
    return archives[0], "sha512-" + base64.b64encode(sha512(data).digest()).decode("ascii")


def _fetch_pypi(work: Path, name: str, version: str) -> tuple[Path, str]:
    endpoint = f"https://pypi.org/pypi/{urllib.parse.quote(name, safe='')}/{urllib.parse.quote(version, safe='')}/json"
    try:
        payload = json.loads(_read_url(endpoint, MAX_PYPI_JSON, PYPI_HOSTS))
    except json.JSONDecodeError as exc:
        raise FetchError("PyPI JSON could not be parsed") from exc
    files = payload.get("urls") if isinstance(payload, dict) else None
    if not isinstance(files, list):
        raise FetchError("PyPI response has no file list")
    usable = [item for item in files if isinstance(item, dict) and isinstance(item.get("url"), str)]
    chosen = next(
        (item for kind in ("sdist", "bdist_wheel") for item in usable if item.get("packagetype") == kind),
        usable[0] if usable else None,
    )
    if chosen is None:
        raise FetchError("PyPI response has no downloadable file")
    data = _read_url(str(chosen["url"]), MAX_BYTES, PYPI_DOWNLOAD_HOSTS)
    digests = chosen.get("digests")
    expected = digests.get("sha256") if isinstance(digests, dict) else None
    actual = sha256(data).hexdigest()
    if not isinstance(expected, str) or expected != actual:
        raise FetchError("downloaded file does not match the PyPI sha256 digest")
    archive = work / "package"
    archive.write_bytes(data)
    return archive, f"sha256:{actual}"


def _fetch_gomod(work: Path, name: str, version: str) -> tuple[Path, str]:
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
    return Path(zip_name), sum_value


def _fetch_action(work: Path, name: str, version: str) -> tuple[Path, str]:
    _run(["git", "init", "-q", "repo"], cwd=work)
    _run(["git", "-C", "repo", "fetch", "--depth", "1", f"https://github.com/{name}", version], cwd=work)
    archive = work / "action.tar"
    archive.write_bytes(
        _run(["git", "-C", "repo", "archive", "--format=tar", "FETCH_HEAD"], cwd=work, text=False).stdout
    )
    return archive, version


ECOSYSTEMS: dict[str, Ecosystem] = {
    "npm_and_yarn": (NPM_NAME, NPM_VERSION, _fetch_npm),
    "pip": (PIP_NAME, PIP_VERSION, _fetch_pypi),
    "gomod": (GO_NAME, GO_VERSION, _fetch_gomod),
    "github_actions": (ACTION_NAME, ACTION_SHA, _fetch_action),
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


def _check(update: Update, ecosystem: Ecosystem, added: list[str], removed: list[str]) -> str | None:
    """Return an unverified reason, or None when the update passes the literal checks."""
    name_pattern, version_pattern, _ = ecosystem
    if not any(update.name in line and update.new_version in line for line in added) or not any(
        update.prev_version in line for line in removed
    ):
        return "name and version were not found on the expected diff lines"
    if not name_pattern.fullmatch(update.name) or not all(
        version_pattern.fullmatch(version) for version in (update.new_version, update.prev_version)
    ):
        return "name or version does not match the ecosystem grammar"
    return None


def _check_budget(count: int, total: int) -> None:
    if count > MAX_FILES:
        raise FetchError("archive exceeds the file-count cap")
    if total > MAX_BYTES:
        raise FetchError("archive exceeds the extracted byte cap")


def _extract(archive: Path, dest: Path) -> None:
    """Extract a tar or zip archive after checking paths, links and size caps."""
    dest.mkdir(parents=True, exist_ok=True)
    try:
        if zipfile.is_zipfile(archive):
            with zipfile.ZipFile(archive) as handle:
                infos = handle.infolist()
                if any(not info.filename or UNSAFE_ZIP_PATH.search(info.filename) for info in infos):
                    raise FetchError("archive contains an unsafe path")
                if any((info.external_attr >> 16) & 0o170000 == 0o120000 for info in infos):
                    raise FetchError("archive contains a symlink")
                _check_budget(len(infos), sum(info.file_size for info in infos if not info.is_dir()))
                handle.extractall(dest)  # ruff: ignore[tarfile-unsafe-members] - names, links and size checked above
        else:
            with tarfile.open(archive, "r:*") as handle:
                members = handle.getmembers()
                _check_budget(len(members), sum(member.size for member in members if not member.isdir()))
                handle.extractall(dest, filter="data")
    except (tarfile.TarError, zipfile.BadZipFile, OSError) as exc:
        raise FetchError(f"extraction failed: {exc}") from exc


def _process_update(index: int, update: Update, out_dir: Path, added: list[str], removed: list[str]) -> Update:
    ecosystem = ECOSYSTEMS.get(update.ecosystem)
    if ecosystem is None:
        return replace(update, status="not_reviewed", note="ecosystem is not reviewed")
    _, _, fetch = ecosystem
    if update.ecosystem == "github_actions" and not ACTION_SHA.fullmatch(update.new_version):
        return replace(update, status="not_reviewed", note="moving ref: the new pin is not a 40-hex commit SHA")
    if note := _check(update, ecosystem, added, removed):
        return replace(update, status="unverified", note=note)
    try:
        slug = f"{index:02d}-" + re.sub(r"[^A-Za-z0-9._@-]", "_", f"{update.name}@{update.new_version}")
        for version, side in ((update.prev_version, "old"), (update.new_version, "new")):
            with tempfile.TemporaryDirectory() as tmp:
                archive, binding = fetch(Path(tmp), update.name, version)
                _extract(archive, out_dir / side / slug)
    except (FetchError, OSError) as exc:
        return replace(update, status="fetch_failed", note=str(exc))
    bound = any(binding in line for line in added)
    return replace(update, bound=bound, note="" if bound else "not bound to the lockfile")


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
    results.extend(
        replace(update, status="not_reviewed", note=f"over the {MAX_UPDATES}-update cap")
        for update in updates[MAX_UPDATES:]
    )
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
