"""Fetch old and new dependency artifacts and write a review bundle."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.parse
import zipfile
from dataclasses import asdict, dataclass, replace
from pathlib import Path, PurePosixPath
from urllib.request import urlopen

SAFE = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9@._/~+-]{0,299}$")
ACTION_SHA = re.compile(r"^[0-9a-f]{40}$")
ECOSYSTEM_ALIASES = {"go_modules": "gomod"}
UPDATE_FIELDS = ("dependencyName", "packageEcosystem", "prevVersion", "newVersion")


class FetchError(Exception):
    pass


@dataclass(frozen=True)
class Update:
    name: str
    ecosystem: str
    directory: str
    prev_version: str
    new_version: str
    status: str = "reviewed"
    note: str = ""


def added_lines(diff: str) -> list[str]:
    return [line[1:] for line in diff.split("\n") if line.startswith("+") and not line.startswith("+++ ")]


def _norm(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def literal_ok(update: Update, added: list[str]) -> bool:
    return any(_norm(update.name) in _norm(line) and update.new_version in line for line in added)


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


def _normalize_versions(update: Update) -> Update:
    if update.ecosystem != "gomod":
        return update
    versions = [v if v.startswith("v") else f"v{v}" for v in (update.prev_version, update.new_version)]
    return replace(update, prev_version=versions[0], new_version=versions[1])


def _run(args: list[str], *, cwd: Path, text: bool = True, ok: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess:
    try:
        proc = subprocess.run(args, cwd=cwd, check=False, capture_output=True, text=text, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FetchError(f"{args[0]} could not run: {exc}") from exc
    if proc.returncode not in ok:
        detail = proc.stderr if isinstance(proc.stderr, str) else proc.stderr.decode("utf-8", "replace")
        raise FetchError(f"{args[0]} exited {proc.returncode}: {detail.strip()[:500]}")
    return proc


def _read_url(url: str) -> bytes:
    try:
        with urlopen(url, timeout=120) as response:  # noqa: S310  # ruff: ignore[noqa-comments]
            return response.read()
    except (OSError, ValueError) as exc:
        raise FetchError(f"download failed: {exc}") from exc


def fetch_npm(work: Path, name: str, version: str) -> Path:
    _run(["npm", "pack", "--ignore-scripts", f"{name}@{version}"], cwd=work)
    archives = sorted(work.glob("*.tgz"))
    if len(archives) != 1:
        raise FetchError("npm pack did not produce exactly one archive")
    return archives[0]


def fetch_pypi(work: Path, name: str, version: str) -> Path:
    endpoint = f"https://pypi.org/pypi/{urllib.parse.quote(name, safe='')}/{urllib.parse.quote(version, safe='')}/json"
    try:
        payload = json.loads(_read_url(endpoint))
    except json.JSONDecodeError as exc:
        raise FetchError("PyPI JSON could not be parsed") from exc
    files = payload.get("urls") if isinstance(payload, dict) else None
    if not isinstance(files, list):
        raise FetchError("PyPI response has no file list")
    usable = [item for item in files if isinstance(item, dict) and isinstance(item.get("url"), str)]
    sdists = [item for item in usable if item.get("packagetype") == "sdist"]
    wheels = [item for item in usable if item.get("packagetype") == "bdist_wheel"]
    selected = (
        sdists or [i for i in wheels if str(i.get("filename", "")).endswith("py3-none-any.whl")] or wheels or [None]
    )[0]
    if selected is None:
        raise FetchError("PyPI response has no sdist or wheel")
    filename = PurePosixPath(str(selected.get("filename", ""))).name
    if not filename or filename in {".", ".."}:
        raise FetchError("PyPI distribution has an unsafe filename")
    path = work / filename
    path.write_bytes(_read_url(selected["url"]))
    return path


def fetch_gomod(work: Path, name: str, version: str) -> Path:
    try:
        payload = json.loads(_run(["go", "mod", "download", "-json", f"{name}@{version}"], cwd=work).stdout)
    except json.JSONDecodeError as exc:
        raise FetchError("go mod download did not return JSON") from exc
    archive = payload.get("Zip") if isinstance(payload, dict) else None
    if not isinstance(archive, str) or not archive:
        raise FetchError("go mod download did not return a zip")
    return Path(archive)


def fetch_action(work: Path, name: str, version: str) -> Path:
    _run(["git", "init", "-q"], cwd=work)
    _run(["git", "fetch", "--depth", "1", f"https://github.com/{name}", version], cwd=work)
    _run(["git", "checkout", "-q", "FETCH_HEAD"], cwd=work)
    _run(["rm", "-rf", ".git"], cwd=work)
    return work


FETCHERS = {
    "npm_and_yarn": fetch_npm,
    "pip": fetch_pypi,
    "gomod": fetch_gomod,
    "github_actions": fetch_action,
}


def _status(update: Update, added: list[str]) -> Update | None:
    if update.ecosystem not in FETCHERS:
        return replace(update, status="not_reviewed", note="ecosystem is not reviewed")
    if update.ecosystem == "github_actions" and not ACTION_SHA.fullmatch(update.new_version):
        return replace(update, status="not_reviewed", note="moving ref: the new pin is not a 40-hex commit SHA")
    if not all(SAFE.fullmatch(value) for value in (update.name, update.prev_version, update.new_version)):
        return replace(update, status="unverified", note="name or version contains unsupported characters")
    if not literal_ok(update, added):
        return replace(update, status="unverified", note="name and new version were not found on an added diff line")
    return None


def extract(source: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    if source.is_dir():
        shutil.copytree(source, dest, dirs_exist_ok=True)
        return
    try:
        if source.name.lower().endswith((".zip", ".whl", ".egg")):
            with zipfile.ZipFile(source) as handle:
                handle.extractall(dest)  # ruff: ignore[tarfile-unsafe-members]
        else:
            with tarfile.open(source, "r:*") as handle:
                handle.extractall(dest, filter="data")
    except (tarfile.TarError, zipfile.BadZipFile, OSError) as exc:
        raise FetchError(f"extraction failed: {exc}") from exc


def write_diff(out_dir: Path) -> None:
    (out_dir / "old").mkdir(exist_ok=True)
    (out_dir / "new").mkdir(exist_ok=True)
    result = _run(["diff", "-ruN", "old", "new"], cwd=out_dir, text=False, ok=(0, 1))
    (out_dir / "changes.diff").write_bytes(result.stdout)


def main() -> int:
    out_dir = Path(os.environ["DCR_OUT"])
    out_dir.mkdir(parents=True, exist_ok=True)
    updates = _parse_updates(os.environ.get("UPDATED_DEPENDENCIES_JSON", ""))
    diff_text = Path(os.environ["PR_DIFF_PATH"]).read_text(encoding="utf-8", errors="replace")
    added = added_lines(diff_text)
    results: list[Update] = []
    for index, update in enumerate(updates):
        if status := _status(update, added):
            results.append(status)
            continue
        slug = f"{index:02d}-" + re.sub(r"[^A-Za-z0-9._@-]", "_", f"{update.name}@{update.new_version}")
        try:
            with tempfile.TemporaryDirectory() as tmp:
                for side, version in (("old", update.prev_version), ("new", update.new_version)):
                    work = Path(tmp) / side
                    work.mkdir()
                    extract(FETCHERS[update.ecosystem](work, update.name, version), out_dir / side / slug)
            results.append(update)
        except (FetchError, OSError) as exc:
            results.append(replace(update, status="fetch_failed", note=str(exc)))
    try:
        write_diff(out_dir)
    except FetchError as exc:
        results = [
            replace(r, status="fetch_failed", note=f"diff failed: {exc}") if r.status == "reviewed" else r
            for r in results
        ]
    reviewable = any(result.status == "reviewed" for result in results)
    meta = {"schema": 1, "updates": [asdict(result) for result in results]}
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if output := os.environ.get("GITHUB_OUTPUT"):
        with Path(output).open("a", encoding="utf-8") as handle:
            handle.write(f"reviewable={str(reviewable).lower()}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
