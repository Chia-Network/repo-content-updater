"""The GitHub repository a primary dependency is scanned from.

A GitHub Action and a github.com Go module name their repository in the
package identity. An npm or PyPI package, and a Go module on another host,
name it in registry or go-get metadata that the publisher controls. Every
answer is a Repo: an `owner/repo` and where the name came from, or Repo()
when none is found.

A repository is verified when the package identity names it, when a
provenance attestation for the installed artifact names it
(dependency_cursor_review_binding.repo_source), or when the allowlist in
dependency_cursor_review_ecosystems maps the package to it. A repository
named only by publisher metadata is not, and decide() never reports a scan
of it benign.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import socket
import threading
import time
import urllib.parse
from collections.abc import Callable, Mapping
from typing import NamedTuple

import dependency_cursor_review_versions as versions

_PART = r"[A-Za-z0-9_.-]+"
_GITHUB_URL_RE = re.compile(
    rf"(?:git\+)?(?:(?:https?|git|ssh)://(?:git@)?|git@)(?:www\.)?github\.com[/:]({_PART})/({_PART})(?:[/#?].*)?",
    re.IGNORECASE,
)
_NPM_SHORTHAND_RE = re.compile(rf"(?:github:)?({_PART})/({_PART})")
_NPM_NAME_RE = re.compile(r"(?:@[A-Za-z0-9._~-]+/)?[A-Za-z0-9._~-]+")
_PYPI_NAME_RE = re.compile(r"[A-Za-z0-9._-]+")
# A module path starts with a dotted host name, never an address or a port.
_GO_MODULE_RE = re.compile(r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?:/[A-Za-z0-9_.~+-]+)+")
_GO_META_RE = re.compile(r"""<meta\s+name=["'](go-import|go-source)["']\s+content=["']([^"']*)["']""", re.IGNORECASE)
_SOURCE_LABEL_RE = re.compile(r"source|repo|code|github", re.IGNORECASE)
_LIMIT = 4 * 1024 * 1024

# Where a repository name came from.
IDENTITY = "identity"  # the package identity: an action's owner/repo, a github.com Go module path
ATTESTED = "attested"  # a provenance attestation for the installed artifact
ALLOWLISTED = "allowlisted"  # dependency_cursor_review_ecosystems.KNOWN_REPOS
PUBLISHER = "publisher"  # registry or go-get metadata the publisher writes
VERIFIED = frozenset({IDENTITY, ATTESTED, ALLOWLISTED})


def verified(source: object) -> bool:
    """A repo_source names a verified repository; a list or object from the JSON never does."""
    return isinstance(source, str) and source in VERIFIED


class Repo(NamedTuple):
    slug: str = ""  # owner/repo, "" when none was found
    source: str = ""  # IDENTITY, ATTESTED, ALLOWLISTED or PUBLISHER; "" with no slug


def _found(slug: str, source: str) -> Repo:
    return Repo(slug, source) if slug else Repo()


def _repo(owner: str, name: str) -> str:
    name = name[:-4] if name.lower().endswith(".git") else name
    if not name or {owner, name} & {".", ".."}:
        return ""
    return f"{owner}/{name}"


def github_repo(url: object) -> str:
    """`owner/repo` of a github.com URL in any git or browser spelling, or ""."""
    match = _GITHUB_URL_RE.fullmatch(url.strip()) if isinstance(url, str) else None
    return _repo(match.group(1), match.group(2)) if match else ""


_REDIRECTS = frozenset({301, 302, 303, 307, 308})
_MAX_REDIRECTS = 5
_TIMEOUT = 20
_CHUNK = 1024 * 1024
_MAX_INDEX_FILE = 512 * 1024 * 1024
_MAX_INDEX_FILES = 64
_FETCH_SECONDS = 120.0
_FETCH_BYTES = 1024 * 1024 * 1024
_INDEX_DOWNLOAD_SECONDS = 120.0
_MAX_INDEX_DOWNLOAD_BYTES = 1024 * 1024 * 1024


def _set_timeout(connection: http.client.HTTPSConnection, budget: _DownloadBudget) -> bool:
    """Set the socket timeout from the budget, or return False when the budget has no time left."""
    remaining = budget.remaining_seconds()
    if remaining <= 0:
        return False
    if connection.sock is not None:
        connection.sock.settimeout(min(_TIMEOUT, remaining))
    return True


class _Deadline:
    """Shut a connection's socket down when its budget deadline passes.

    The timer bounds the request, the status and header lines, and each body or chunk-size read, including one that
    arrives in many small pieces. The connect and TLS handshake are bounded by the per-operation socket timeout, the
    smaller of _TIMEOUT and the time remaining. The timer sets `fired` before it shuts the socket down, so a read that
    ends at the deadline is a failure rather than the end of a body.
    """

    def __init__(self, connection: http.client.HTTPSConnection, budget: _DownloadBudget) -> None:
        self._connection = connection
        self.fired = False
        self._timer = threading.Timer(max(0.0, budget.remaining_seconds()), self._expire)
        self._timer.daemon = True
        self._timer.start()

    def _expire(self) -> None:
        self.fired = True
        sock = getattr(self._connection, "sock", None)
        shutdown = getattr(sock, "shutdown", None)
        if shutdown is not None:
            try:
                shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        close = getattr(sock, "close", None)
        if close is not None:
            try:
                close()
            except OSError:
                pass

    def cancel(self) -> None:
        self._timer.cancel()


def _close(connection: http.client.HTTPSConnection) -> None:
    """Cancel a connection's deadline timer, if any, and close it."""
    deadline = getattr(connection, "_deadline", None)
    if deadline is not None:
        deadline.cancel()
    connection.close()


def _connect(parts: urllib.parse.SplitResult, timeout: float) -> http.client.HTTPSConnection:
    """An https connection to `parts`, with the socket operation timeout."""
    return http.client.HTTPSConnection(parts.hostname, parts.port, timeout=timeout)


def _read_chunk(
    connection: http.client.HTTPSConnection,
    response: http.client.HTTPResponse,
    size: int,
    budget: _DownloadBudget,
) -> bytes | None:
    """Up to `size` bytes from `response`, or None at or past the deadline."""
    deadline = getattr(connection, "_deadline", None)
    if (deadline is not None and deadline.fired) or not _set_timeout(connection, budget):
        return None
    chunk = response.read1(size)
    return None if deadline is not None and deadline.fired else chunk


def _get_response(
    url: str,
    accept: str,
    budget: _DownloadBudget | None = None,
) -> tuple[http.client.HTTPSConnection, http.client.HTTPResponse] | None:
    """An open response to an https GET and its connection, or None when there is none within `budget`."""
    budget = budget or _DownloadBudget()
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        return None
    remaining = budget.remaining_seconds()
    if remaining <= 0:
        return None
    target = parts.path + (f"?{parts.query}" if parts.query else "")
    connection = _connect(parts, min(_TIMEOUT, remaining))
    if budget.remaining_seconds() <= 0:
        connection.close()
        return None
    connection._deadline = _Deadline(connection, budget)
    try:
        connection.request("GET", target, headers={"Accept": accept, "User-Agent": "dependency-review"})
        if not _set_timeout(connection, budget):
            _close(connection)
            return None
        return connection, connection.getresponse()
    except (OSError, http.client.HTTPException):
        _close(connection)
        return None


def _get(
    url: str,
    limit: int,
    accept: str = "application/json",
    budget: _DownloadBudget | None = None,
) -> tuple[int, str, bytes] | None:
    """The status, Location header and first `limit + 1` body bytes of an https GET, or None when there is none."""
    budget = budget or _DownloadBudget()
    opened = _get_response(url, accept, budget)
    if opened is None:
        return None
    connection, response = opened
    try:
        body = bytearray()
        while len(body) <= limit:
            chunk = _read_chunk(connection, response, min(_CHUNK, limit + 1 - len(body)), budget)
            if chunk is None:
                return None
            if not chunk:
                break
            body.extend(chunk)
        return response.status, response.getheader("Location") or "", bytes(body)
    except (OSError, http.client.HTTPException):
        return None
    finally:
        _close(connection)


def _has_dot_segment(path: str) -> bool:
    """Whether `path` has a `.` or `..` segment, including one written with percent escapes."""
    return any(segment in {".", ".."} for segment in urllib.parse.unquote(path).split("/"))


def _redirect_allowed(url: str, follow: Mapping[str, str] | None) -> bool:
    """An https URL on a host in `follow`, within that host's required path prefix ("" permits any path).

    A path with a `.` or `..` segment is never allowed.
    """
    parts = urllib.parse.urlsplit(url)
    prefix = follow.get(parts.hostname) if follow and parts.hostname else None
    return (
        parts.scheme == "https"
        and prefix is not None
        and parts.path.startswith(prefix)
        and not _has_dot_segment(parts.path)
    )


def _fetch(
    url: str,
    limit: int = _LIMIT,
    follow: Mapping[str, str] | None = None,
    accept: str = "application/json",
    budget: _DownloadBudget | None = None,
) -> bytes | None:
    """The body of a 200 response to an https GET, b"" for a 404, or None when there is no readable answer.

    A redirect is followed only to an https URL on a host in `follow`, within that host's path prefix, and at most
    _MAX_REDIRECTS times. `budget` covers every redirect hop and body read.
    """
    budget = budget or _DownloadBudget()
    for _hop in range(_MAX_REDIRECTS + 1):
        answer = _get(url, limit, accept, budget)
        if answer is None:
            return None
        status, location, body = answer
        if status not in _REDIRECTS:
            break
        url = urllib.parse.urljoin(url, location)
        if not location or not _redirect_allowed(url, follow):
            return None
    else:
        return None
    if status == 404:
        return b""
    return body if status == 200 and len(body) <= limit else None


def fetch_archive(url: str, limit: int, follow: Mapping[str, str] | None = None) -> bytes | None:
    """The body of a 200 response to an https GET of at most `limit` bytes, or None for anything else.

    A redirect is followed only to a host in `follow`, within that host's path prefix.
    """
    return _fetch(url, limit, follow) or None


class _DownloadBudget:
    """The time and total byte allowance of one fetch.

    A non-index fetch gets _FETCH_SECONDS and _FETCH_BYTES. A trusted index check gets its own limits and passes them
    explicitly. A grouped update runs one package check per package, so it can take up to N times these limits.
    """

    def __init__(
        self,
        seconds: float | None = None,
        size: int | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._clock = clock
        self.deadline = clock() + (_FETCH_SECONDS if seconds is None else seconds)
        self.remaining = _FETCH_BYTES if size is None else size

    def remaining_seconds(self) -> float:
        return self.deadline - self._clock()

    def expired(self) -> bool:
        return self.remaining_seconds() <= 0

    def take(self, size: int) -> bool:
        """Consume `size` bytes, or return False when they exceed what is left."""
        if size > self.remaining:
            return False
        self.remaining -= size
        return True


def _sha256_download(
    url: str,
    hosts: frozenset[str],
    limit: int = _MAX_INDEX_FILE,
    budget: _DownloadBudget | None = None,
) -> str | None:
    """The sha256 of an https GET body from a host in `hosts`, or None when it is not a 200 or exceeds `limit` bytes.

    The body is read in chunks. A redirect is followed only to a host in `hosts`, and at most _MAX_REDIRECTS times.
    `budget` bounds the whole check's time and bytes; a limit that it hits gives no digest.
    """
    budget = budget or _DownloadBudget()
    for _hop in range(_MAX_REDIRECTS + 1):
        if budget.expired():
            return None
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" or parts.hostname not in hosts:
            return None
        opened = _get_response(url, "application/octet-stream", budget)
        if opened is None:
            return None
        connection, response = opened
        try:
            if response.status in _REDIRECTS:
                location = response.getheader("Location") or ""
                if not location:
                    return None
                url = urllib.parse.urljoin(url, location)
                continue
            if response.status != 200:
                return None
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = _read_chunk(connection, response, _CHUNK, budget)
                if chunk is None:
                    return None
                if not chunk:
                    break
                size += len(chunk)
                if size > limit or not budget.take(len(chunk)) or budget.expired():
                    return None
                digest.update(chunk)
            return digest.hexdigest()
        except (OSError, http.client.HTTPException):
            return None
        finally:
            _close(connection)
    return None


def fetch_json(url: str) -> dict | None:
    """The JSON object an https GET answers with, {} for a 404, or None when there is no readable object."""
    body = _fetch(url)
    if not body:
        return None if body is None else {}
    try:
        doc = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def action(name: str, _version: str) -> Repo:
    """`owner/repo` of `owner/repo[/path]`."""
    owner, _, rest = name.partition("/")
    return _found(_repo(owner, rest.split("/", 1)[0]) if re.fullmatch(_PART, owner) and rest else "", IDENTITY)


def npm_path(name: str) -> str:
    """A validated package name as one registry URL path segment: a scope's `/` is `%2F`, "" when it is no name."""
    return urllib.parse.quote(name, safe="@") if _NPM_NAME_RE.fullmatch(name) else ""


def _npm_repository(name: str, version: str) -> str:
    path = npm_path(name)
    if not path:
        return ""
    doc = fetch_json(f"https://registry.npmjs.org/{path}/{urllib.parse.quote(version, safe='')}") or {}
    repository = doc.get("repository")
    url = repository.get("url") if isinstance(repository, dict) else repository
    if not isinstance(url, str):
        return ""
    shorthand = _NPM_SHORTHAND_RE.fullmatch(url.strip())
    return _repo(shorthand.group(1), shorthand.group(2)) if shorthand else github_repo(url)


def npm(name: str, version: str) -> Repo:
    """The version document's `repository`: a URL, `{url}`, or `owner/repo` / `github:owner/repo` shorthand."""
    return _found(_npm_repository(name, version), PUBLISHER)


def _pypi_repository(name: str, version: str) -> str:
    if not _PYPI_NAME_RE.fullmatch(name):
        return ""
    quoted = urllib.parse.quote(version, safe="")
    info = (fetch_json(f"https://pypi.org/pypi/{name}/{quoted}/json") or {}).get("info")
    if not isinstance(info, dict):
        return ""
    urls = info.get("project_urls") if isinstance(info.get("project_urls"), dict) else {}
    labelled = sorted(urls.items(), key=lambda item: not _SOURCE_LABEL_RE.search(str(item[0])))
    return next(filter(None, map(github_repo, [url for _label, url in labelled] + [info.get("home_page")])), "")


def pypi(name: str, version: str) -> Repo:
    """The first GitHub project URL, source-like labels before the home page."""
    return _found(_pypi_repository(name, version), PUBLISHER)


def _go_get_repository(module: str) -> str:
    page = (_fetch(f"https://{module}?go-get=1") or b"").decode("utf-8", errors="replace")
    metas = [(kind.lower(), content.split()) for kind, content in _GO_META_RE.findall(page)]
    for want, index in (("go-import", 2), ("go-source", 1)):
        for kind, fields in metas:
            prefix = fields[0] if fields else ""
            if kind == want and len(fields) > index and (module == prefix or module.startswith(prefix + "/")):
                found = github_repo(fields[index])
                if found:
                    return found
    return ""


def go(module: str, _version: str) -> Repo:
    """github.com/owner/repo from the module path, else the go-import or go-source GitHub URL for the module."""
    if not _GO_MODULE_RE.fullmatch(module):
        return Repo()
    parts = module.split("/")
    if parts[0] == "github.com":
        return _found(_repo(parts[1], parts[2]) if len(parts) >= 3 else "", IDENTITY)
    return _found(_go_get_repository(module), PUBLISHER)


# Deliberate trust decision (AGENTS.md, "Trusted package indexes"): a Python package that one of the organization's
# own indexes below serves at the exact version is trusted and is not scanned when every file hash the lock records
# matches a file downloaded from it, or, for an unhashed occurrence, when the requirements file that pins it replaces
# PyPI with that index. This tuple is the only list of trusted indexes. A repository's Dependabot config can select
# among them, but nothing a repository or a package says can add one; any other configured index leaves pip changes
# inconclusive.
TRUSTED_PYTHON_INDEXES = ("https://pypi.chia.net/simple/", "https://download.chia.net/simple/")
# A trusted index may serve its files from another host. A link and a download redirect may reach only the index's
# own host or a host listed here.
TRUSTED_PYTHON_INDEX_FILE_HOSTS: Mapping[str, frozenset[str]] = {
    "https://pypi.chia.net/simple/": frozenset({"download.chia.net"}),
}
_INDEX_LINK_RE = re.compile(r"""<a\s[^>]*?href=["']([^"']+)["']""", re.IGNORECASE)
_SDIST_SUFFIXES = (".tar.gz", ".zip", ".tar.bz2")


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _release(filename: str) -> tuple[str, str]:
    """(canonical project name, version) of a wheel or sdist file name, or ("", "")."""
    if filename.endswith(".whl"):
        parts = filename.removesuffix(".whl").split("-")
        return (_canonical(parts[0]), parts[1]) if len(parts) >= 5 else ("", "")
    for suffix in _SDIST_SUFFIXES:
        if filename.endswith(suffix):
            name, _, version = filename.removesuffix(suffix).rpartition("-")
            return (_canonical(name), version) if name else ("", "")
    return ("", "")


def _index_hosts(index: str) -> frozenset[str]:
    """The hosts a trusted index may serve its page and files from."""
    host = urllib.parse.urlsplit(index).hostname
    return frozenset({host, *TRUSTED_PYTHON_INDEX_FILE_HOSTS.get(index, ())}) if host else frozenset()


def _index_files(index: str, name: str, version: str, budget: _DownloadBudget) -> tuple[str, ...] | None:
    """The urls of the files a simple index page lists for `name` at `version`, or None.

    Versions are compared in their canonical PEP 440 form. The page is read with a bounded regex scan, following
    redirects only to the index's hosts over https and within `budget`. A page that cannot be read, lists no file
    for the version, or lists more than _MAX_INDEX_FILES of them, leaves the package untrusted.
    """
    wanted = versions.pep440_key(version)
    if not wanted:
        return None
    page_url = f"{index}{_canonical(name)}/"
    hosts = _index_hosts(index)
    body = _fetch(page_url, accept="text/html", follow={host: "" for host in hosts}, budget=budget)
    if not body:
        return None
    files: list[str] = []
    for href in _INDEX_LINK_RE.findall(body.decode("utf-8", errors="replace")):
        url = urllib.parse.urljoin(page_url, href.replace("&amp;", "&"))
        parts = urllib.parse.urlsplit(url)
        found_name, found_version = _release(urllib.parse.unquote(parts.path.rsplit("/", 1)[-1]))
        if found_name != _canonical(name) or versions.pep440_key(found_version) != wanted:
            continue
        if parts.scheme != "https" or parts.hostname not in hosts:
            return None
        files.append(urllib.parse.urlunsplit(parts._replace(fragment="")))
    return tuple(files) if files and len(files) <= _MAX_INDEX_FILES else None


class Locked(NamedTuple):
    """One occurrence of a package in a lock or requirements file."""

    hashes: str = ""  # space-separated sha256 values, "" when the occurrence records none
    index: str = ""  # the trusted index its file replaces PyPI with, "" when it does not


def _serves_wanted(files: tuple[str, ...], hosts: frozenset[str], wanted: set[str], budget: _DownloadBudget) -> bool:
    """Whether `files` serve every wanted digest, stopping once they all match.

    A file that cannot be read or a budget limit means no match.
    """
    found: set[str] = set()
    for url in files:
        if wanted <= found:
            return True
        digest = _sha256_download(url, hosts, budget=budget)
        if digest is None:
            return False
        found.add(digest)
    return wanted <= found


def trusted_python_index(
    name: str,
    version: str,
    locked: tuple[Locked, ...],
    configured: frozenset[str],
) -> str:
    """The host of a trusted index in `configured` that serves `name` at `version`, or "".

    An unhashed occurrence must name the trusted index its file installs from, and every such index must serve
    `name` at this version. Each sha256 a hashed occurrence records must match a file downloaded from a trusted
    index at this version. A file link outside the index's hosts is not downloaded. One budget covers this
    package check, including the index page and every file read; a grouped update runs one check per package.
    """
    if not _PYPI_NAME_RE.fullmatch(name) or not version:
        return ""
    required = {item.index for item in locked if not item.hashes}
    if any(not item.hashes and not item.index for item in locked):
        return ""
    wanted = {digest.removeprefix("sha256:").lower() for item in locked for digest in item.hashes.split()}
    if not wanted and not required:
        return ""
    served: set[str] = set()
    matched = ""
    budget = _DownloadBudget(seconds=_INDEX_DOWNLOAD_SECONDS, size=_MAX_INDEX_DOWNLOAD_BYTES)
    for index in TRUSTED_PYTHON_INDEXES:
        if index not in configured:
            continue
        files = _index_files(index, name, version, budget)
        if not files:
            continue
        hosts = _index_hosts(index)
        if index in required:
            served.add(index)
        if wanted and not matched and _serves_wanted(files, hosts, wanted, budget):
            matched = index
    if required - served or (wanted and not matched):
        return ""
    chosen = next(index for index in TRUSTED_PYTHON_INDEXES if index in required) if required else matched
    return urllib.parse.urlsplit(chosen).hostname or ""
