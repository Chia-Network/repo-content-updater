"""The GitHub repository a primary dependency is scanned from.

A GitHub Action and a github.com Go module name their repository in the
package identity. An npm or PyPI package, and a Go module on another host,
name it in registry or go-get metadata that the publisher controls. Every
answer is an `owner/repo`, or "" when none is found.
"""

from __future__ import annotations

import http.client
import json
import re
import urllib.parse

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


def _repo(owner: str, name: str) -> str:
    name = name[:-4] if name.lower().endswith(".git") else name
    if not name or {owner, name} & {".", ".."}:
        return ""
    return f"{owner}/{name}"


def github_repo(url: object) -> str:
    """`owner/repo` of a github.com URL in any git or browser spelling, or ""."""
    match = _GITHUB_URL_RE.fullmatch(url.strip()) if isinstance(url, str) else None
    return _repo(match.group(1), match.group(2)) if match else ""


def _fetch(url: str) -> bytes:
    """The body of a 200 response to an https GET, or b"" otherwise. Redirects are not followed."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        return b""
    target = parts.path + (f"?{parts.query}" if parts.query else "")
    connection = http.client.HTTPSConnection(parts.hostname, timeout=20)
    try:
        connection.request("GET", target, headers={"Accept": "application/json", "User-Agent": "dependency-review"})
        response = connection.getresponse()
        body = response.read(_LIMIT + 1) if response.status == 200 else b""
    except (OSError, http.client.HTTPException):
        return b""
    finally:
        connection.close()
    return body if len(body) <= _LIMIT else b""


def fetch_json(url: str) -> dict:
    """The JSON object an https GET answers with, or {} for any other answer."""
    try:
        doc = json.loads(_fetch(url).decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def action(name: str, _version: str) -> str:
    """`owner/repo` of `owner/repo[/path]`."""
    owner, _, rest = name.partition("/")
    return _repo(owner, rest.split("/", 1)[0]) if re.fullmatch(_PART, owner) and rest else ""


def npm(name: str, version: str) -> str:
    """The version document's `repository`: a URL, `{url}`, or `owner/repo` / `github:owner/repo` shorthand."""
    if not _NPM_NAME_RE.fullmatch(name):
        return ""
    doc = fetch_json(f"https://registry.npmjs.org/{name}/{urllib.parse.quote(version, safe='')}")
    repository = doc.get("repository")
    url = repository.get("url") if isinstance(repository, dict) else repository
    if not isinstance(url, str):
        return ""
    shorthand = _NPM_SHORTHAND_RE.fullmatch(url.strip())
    return _repo(shorthand.group(1), shorthand.group(2)) if shorthand else github_repo(url)


def pypi(name: str, version: str) -> str:
    """The first GitHub project URL, source-like labels before the home page."""
    if not _PYPI_NAME_RE.fullmatch(name):
        return ""
    quoted = urllib.parse.quote(version, safe="")
    info = fetch_json(f"https://pypi.org/pypi/{name}/{quoted}/json").get("info")
    if not isinstance(info, dict):
        return ""
    urls = info.get("project_urls") if isinstance(info.get("project_urls"), dict) else {}
    labelled = sorted(urls.items(), key=lambda item: not _SOURCE_LABEL_RE.search(str(item[0])))
    for url in [url for _label, url in labelled] + [info.get("home_page")]:
        found = github_repo(url)
        if found:
            return found
    return ""


def go(module: str, _version: str) -> str:
    """github.com/owner/repo from the module path, else the go-import or go-source GitHub URL for the module."""
    if not _GO_MODULE_RE.fullmatch(module):
        return ""
    parts = module.split("/")
    if parts[0] == "github.com":
        return _repo(parts[1], parts[2]) if len(parts) >= 3 else ""
    page = _fetch(f"https://{module}?go-get=1").decode("utf-8", errors="replace")
    metas = [(kind.lower(), content.split()) for kind, content in _GO_META_RE.findall(page)]
    for want, index in (("go-import", 2), ("go-source", 1)):
        for kind, fields in metas:
            prefix = fields[0] if fields else ""
            if kind == want and len(fields) > index and (module == prefix or module.startswith(prefix + "/")):
                found = github_repo(fields[index])
                if found:
                    return found
    return ""
