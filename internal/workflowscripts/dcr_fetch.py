"""Fetch old and new dependency artifacts and write a review bundle."""

from __future__ import annotations

import json
import os
import re
import shlex
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
ACTION_TAG = r"v[0-9]+(?:\.[0-9]+){0,2}"
FULL_TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
ECOSYSTEM_ALIASES = {"go_modules": "gomod"}
UPDATE_FIELDS = ("dependencyName", "packageEcosystem", "newVersion", "prevVersion")


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
    prev_commit: str = ""
    new_commit: str = ""


def added_lines(diff: str) -> list[str]:
    return [line[1:] for line in diff.split("\n") if line.startswith("+") and not line.startswith("+++ ")]


def _norm(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def literal_ok(update: Update, added: list[str]) -> bool:
    version = re.compile(rf"(?<![0-9A-Za-z.]){re.escape(update.new_version)}(?![0-9A-Za-z]|\.[0-9])")
    return any(_norm(update.name) in _norm(line) and version.search(line) for line in added)


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
        if not all(isinstance(v, str) and v for v in values[:3]) or not isinstance(values[3] or "", str):
            raise SystemExit("updated dependency is missing a required field")
        directory = entry if isinstance(entry := item.get("directory", ""), str) else ""
        name, ecosystem, new_version, prev_version = values
        prev_version = prev_version if isinstance(prev_version, str) else ""
        update = Update(name, ECOSYSTEM_ALIASES.get(ecosystem, ecosystem), directory, prev_version, new_version)
        updates.append(_normalize_versions(update))
    return updates


def _normalize_versions(update: Update) -> Update:
    if update.ecosystem != "gomod":
        return update
    versions = [v if not v or v.startswith("v") else f"v{v}" for v in (update.prev_version, update.new_version)]
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
    if len(archives) != 1 or not archives[0].name.endswith(f"-{version}.tgz"):
        raise FetchError("npm pack did not produce the requested version")
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
    if not isinstance(archive, str) or not archive or payload.get("Version") != version:
        raise FetchError("go mod download did not return the requested version")
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


def _action_refs(name: str, diff: str, ref: str = "[0-9a-f]{40}") -> tuple[dict[str, str], set[str]]:
    """Return removed refs mapped to their diff lines, and added refs, for one action."""
    pattern = re.compile(rf"uses:\s*[\"']?(?i:{re.escape(name)})(?:/[^@\s]*)?@({ref})(?=[\"'\s]|$)")
    found: dict[str, dict[str, str]] = {"-": {}, "+": {}}
    for line in diff.split("\n"):
        if line[:1] in found and not line.startswith(("--- ", "+++ ")) and (match := pattern.search(line)):
            found[line[0]].setdefault(match.group(1), line)
    return found["-"], set(found["+"])


def _prev_sha(old: dict[str, str], version: str) -> str:
    wanted, comment = version.removeprefix("v"), re.compile(r"#\s*v?(\S+)")
    matches = (sha for sha, line in old.items() if (match := comment.search(line)) and match.group(1) == wanted)
    return next(matches, sorted(old)[0])


def resolve_tag(name: str, tag: str) -> str:
    """Resolve a tag to its commit with git ls-remote, peeling annotated tags; fail on missing or ambiguous refs."""
    out = _run(["git", "ls-remote", f"https://github.com/{name}", tag], cwd=Path(tempfile.gettempdir())).stdout
    refs = dict(reversed(line.split("\t", 1)) for line in out.splitlines() if "\t" in line)
    if f"refs/heads/{tag}" in refs:
        raise FetchError(f"{tag} is ambiguous: a branch has the same name")
    sha = refs.get(f"refs/tags/{tag}" + "^{}") or refs.get(f"refs/tags/{tag}", "")
    if not ACTION_SHA.fullmatch(sha):
        raise FetchError(f"{tag} did not resolve to a commit")
    return sha


def _action_status(update: Update, diff: str) -> Update | None:
    """Pin SHAs or resolve tags for an action; None means fall through to the generic checks."""
    old, new = _action_refs(update.name, diff)
    if len(new) == 1 and old:
        return replace(update, prev_version=_prev_sha(old, update.prev_version), new_version=new.pop())
    if new:
        return replace(update, status="unverified", note="the diff does not identify one old and one new SHA")
    if ACTION_SHA.fullmatch(update.new_version):
        return update
    old_tags, new_tags = _action_refs(update.name, diff, ACTION_TAG)
    if not old_tags and not new_tags:
        return replace(update, status="not_reviewed", note="the pin is not a version tag or a 40-hex commit SHA")
    if len(new_tags) != 1 or not old_tags:
        return replace(update, status="unverified", note="the diff does not identify one old and one new tag")
    prev_tag = next(
        (t for t in old_tags if t.removeprefix("v") == update.prev_version.removeprefix("v")), min(old_tags)
    )
    update = replace(update, prev_version=prev_tag, new_version=new_tags.pop())
    try:
        commits = [resolve_tag(update.name, tag) for tag in (update.prev_version, update.new_version)]
    except FetchError as exc:
        return replace(update, status="unverified", note=f"tag did not resolve: {exc}")
    return replace(update, prev_commit=commits[0], new_commit=commits[1])


def _status(update: Update, diff: str) -> Update:
    if update.ecosystem not in FETCHERS:
        return replace(update, status="not_reviewed", note="ecosystem is not reviewed")
    if update.ecosystem == "github_actions":
        update = _action_status(update, diff) or update
        if update.status != "reviewed":
            return update
    if not update.prev_version:
        return replace(update, status="unverified", note="previous version is missing")
    if not all(SAFE.fullmatch(value) for value in (update.name, update.prev_version, update.new_version)):
        return replace(update, status="unverified", note="name or version contains unsupported characters")
    if not literal_ok(update, added_lines(diff)):
        return replace(update, status="unverified", note="name and new version were not found on an added diff line")
    return update


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
    while len(entries := list(dest.iterdir())) == 1 and entries[0].is_dir():
        top, placeholder = entries[0], Path(tempfile.mkdtemp(dir=dest, prefix=".collapse-"))
        placeholder.rmdir()
        top.rename(placeholder)
        for child in list(placeholder.iterdir()):
            child.rename(dest / child.name)
        placeholder.rmdir()


def write_diff(out_dir: Path) -> None:
    (out_dir / "old").mkdir(exist_ok=True)
    (out_dir / "new").mkdir(exist_ok=True)
    result = _run(["diff", "-ruN", "old", "new"], cwd=out_dir, text=False, ok=(0, 1))
    (out_dir / "changes.diff").write_bytes(result.stdout)


MANIFESTS = {"package.json", "setup.py", "setup.cfg", "pyproject.toml", "go.mod", "action.yml", "action.yaml"}


def _major(version: str) -> str:
    return re.split(r"[.+-]", version.lstrip("vV"), maxsplit=1)[0]


def _diff_header_path(paths: str) -> str:
    """The new-side path of a "diff -ruN old/P new/P" header; GNU diff quotes P when it has spaces."""
    try:
        parts = shlex.split(paths)
    except ValueError:
        parts = []
    if len(parts) == 2:
        return parts[1]
    # Unquoted "old/P new/P" where P contains spaces: both halves are the same length.
    return paths[len(paths) - (len(paths) - 9) // 2 :]


def collect_facts(results: list[Update], diff: bytes) -> list[str]:
    """Plain, script-computed facts about the update for the agent and the comment."""
    facts = [
        f"{r.name}: major version change {r.prev_version} -> {r.new_version}"
        for r in results
        if r.status == "reviewed"
        and r.ecosystem != "github_actions"
        and _major(r.prev_version) != _major(r.new_version)
    ]
    for r in results:
        if r.status != "reviewed" or not r.new_commit:
            continue
        facts.append(f"{r.name}: tag {r.prev_version} resolved to {r.prev_commit}, {r.new_version} to {r.new_commit}")
        if not FULL_TAG.fullmatch(r.new_version):
            facts.append(f"{r.name}: {r.new_version} can move after review; the reviewed commit was {r.new_commit}")
    binary = 0
    manifests: set[str] = set()
    for line in diff.decode("utf-8", errors="replace").splitlines():
        if line.startswith("diff -ruN "):
            name = PurePosixPath(_diff_header_path(line[len("diff -ruN ") :])).name
            if name in MANIFESTS:
                manifests.add(name)
        elif line.startswith("Binary files "):
            binary += 1
    facts += [f"manifest or build file changed: {name}" for name in sorted(manifests)]
    if binary:
        facts.append(f"binary files changed: {binary}")
    return facts


def main() -> int:
    out_dir = Path(os.environ["DCR_OUT"])
    out_dir.mkdir(parents=True, exist_ok=True)
    updates = _parse_updates(os.environ.get("UPDATED_DEPENDENCIES_JSON", ""))
    diff_text = Path(os.environ["PR_DIFF_PATH"]).read_text(encoding="utf-8", errors="replace")
    results: list[Update] = []
    for index, update in enumerate(updates):
        resolved = _status(update, diff_text)
        if resolved.status != "reviewed":
            results.append(resolved)
            continue
        slug = f"{index:02d}-" + re.sub(r"[^A-Za-z0-9._@-]", "_", f"{resolved.name}@{resolved.new_version}")
        try:
            with tempfile.TemporaryDirectory() as tmp:
                sides = (
                    ("old", resolved.prev_commit or resolved.prev_version),
                    ("new", resolved.new_commit or resolved.new_version),
                )
                for side, version in sides:
                    work = Path(tmp) / side
                    work.mkdir()
                    extract(FETCHERS[resolved.ecosystem](work, resolved.name, version), out_dir / side / slug)
            results.append(resolved)
        except (FetchError, OSError) as exc:
            results.append(replace(resolved, status="fetch_failed", note=str(exc)))
    try:
        write_diff(out_dir)
    except FetchError as exc:
        results = [
            replace(r, status="fetch_failed", note=f"diff failed: {exc}") if r.status == "reviewed" else r
            for r in results
        ]
    reviewable = any(result.status == "reviewed" for result in results)
    diff_path = out_dir / "changes.diff"
    facts = collect_facts(results, diff_path.read_bytes() if diff_path.exists() else b"")
    meta = {"schema": 1, "updates": [asdict(result) for result in results], "facts": facts}
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if output := os.environ.get("GITHUB_OUTPUT"):
        with Path(output).open("a", encoding="utf-8") as handle:
            handle.write(f"reviewable={str(reviewable).lower()}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
