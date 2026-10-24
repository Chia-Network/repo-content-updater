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
import urllib.parse
from collections.abc import Mapping
from typing import NamedTuple


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


def _get_response(url: str, accept: str) -> tuple[http.client.HTTPSConnection, http.client.HTTPResponse] | None:
    """An open response to an https GET and its connection, or None when there is none."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        return None
    target = parts.path + (f"?{parts.query}" if parts.query else "")
    connection = http.client.HTTPSConnection(parts.hostname, timeout=_TIMEOUT)
    try:
        connection.request("GET", target, headers={"Accept": accept, "User-Agent": "dependency-review"})
        return connection, connection.getresponse()
    except (OSError, http.client.HTTPException):
        connection.close()
        return None


def _get(url: str, limit: int, accept: str = "application/json") -> tuple[int, str, bytes] | None:
    """The status, Location header and first `limit + 1` body bytes of an https GET, or None when there is none."""
    opened = _get_response(url, accept)
    if opened is None:
        return None
    connection, response = opened
    try:
        return response.status, response.getheader("Location") or "", response.read(limit + 1)
    except (OSError, http.client.HTTPException):
        return None
    finally:
        connection.close()


def _redirect_allowed(url: str, follow: Mapping[str, str] | None) -> bool:
    """An https URL on a host in `follow`, within that host's required path prefix ("" permits any path)."""
    parts = urllib.parse.urlsplit(url)
    prefix = follow.get(parts.hostname) if follow and parts.hostname else None
    return parts.scheme == "https" and prefix is not None and parts.path.startswith(prefix)


def _fetch(
    url: str,
    limit: int = _LIMIT,
    follow: Mapping[str, str] | None = None,
    accept: str = "application/json",
) -> bytes | None:
    """The body of a 200 response to an https GET, b"" for a 404, or None when there is no readable answer.

    A redirect is followed only to an https URL on a host in `follow`, within that host's path prefix, and at most
    _MAX_REDIRECTS times.
    """
    for _hop in range(_MAX_REDIRECTS + 1):
        answer = _get(url, limit, accept)
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


def _sha256_download(url: str, host: str, limit: int = _MAX_INDEX_FILE) -> str | None:
    """The sha256 of an https GET body from `host`, or None when it is not a 200 or exceeds `limit` bytes.

    The body is read in chunks. A redirect is followed only to `host`, and at most _MAX_REDIRECTS times.
    """
    for _hop in range(_MAX_REDIRECTS + 1):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" or parts.hostname != host:
            return None
        opened = _get_response(url, "application/octet-stream")
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
            while chunk := response.read(_CHUNK):
                size += len(chunk)
                if size > limit:
                    return None
                digest.update(chunk)
            return digest.hexdigest()
        except (OSError, http.client.HTTPException):
            return None
        finally:
            connection.close()
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
# matches a file downloaded from it, or, for an unhashed pin, when that index replaces PyPI. This tuple is the only
# list of trusted indexes. A repository's Dependabot config can select among them, but nothing a repository or a
# package says can add one; any other configured index leaves pip changes inconclusive.
TRUSTED_PYTHON_INDEXES = ("https://pypi.chia.net/simple/", "https://download.chia.net/simple/")
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


def _index_files(index: str, name: str, version: str) -> tuple[str, ...] | None:
    """The urls of the files a simple index page lists for `name` at `version`, or None.

    Each url is resolved against the page and must be https on the index host. A page with no file for the version,
    or with more than _MAX_INDEX_FILES of them, has none.
    """
    page_url = f"{index}{_canonical(name)}/"
    body = _fetch(page_url, accept="text/html")
    if not body:
        return None
    host = urllib.parse.urlsplit(index).hostname
    files: list[str] = []
    for href in _INDEX_LINK_RE.findall(body.decode("utf-8", errors="replace")):
        url = urllib.parse.urljoin(page_url, href.replace("&amp;", "&"))
        parts = urllib.parse.urlsplit(url)
        if _release(urllib.parse.unquote(parts.path.rsplit("/", 1)[-1])) != (_canonical(name), version):
            continue
        if parts.scheme != "https" or not host or parts.hostname != host:
            return None
        files.append(urllib.parse.urlunsplit(parts._replace(fragment="")))
    return tuple(files) if files and len(files) <= _MAX_INDEX_FILES else None


def trusted_python_index(
    name: str,
    version: str,
    locked: tuple[str, ...],
    configured: frozenset[str],
    replaces_pypi: bool = False,
) -> str:
    """The host of the first trusted index in `configured` that serves `name` at `version`, or "".

    With a hashed lock, each sha256 the lock records (`locked`, as binding.Subject.locked) must match a file
    downloaded from that index at this version. With an unhashed pin, the index must replace PyPI (`replaces_pypi`).
    A file link outside the index host is not downloaded.
    """
    if not _PYPI_NAME_RE.fullmatch(name) or not version:
        return ""
    wanted = {digest.removeprefix("sha256:").lower() for hashes in locked for digest in hashes.split()}
    if not wanted and not replaces_pypi:
        return ""
    for index in TRUSTED_PYTHON_INDEXES:
        if index not in configured:
            continue
        files = _index_files(index, name, version)
        if not files:
            continue
        host = urllib.parse.urlsplit(index).hostname or ""
        if not wanted:
            return host
        downloaded = [_sha256_download(url, host) for url in files]
        if all(digest is not None for digest in downloaded) and wanted <= {digest for digest in downloaded if digest}:
            return host
    return ""
